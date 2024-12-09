#pragma once

#include <iostream>
#include <pcap/pcap.h>

#include "PcapDevice.h"
#include "PcapFileDevice.h"

#define TMP_LOG(message)                   \
    do {                                   \
        std::cerr << message << std::endl; \
    } while (0)

namespace pcpp {

/**
 * @class IShmDevice
 * An abstract class representing a shared memory device.
 */
class IShmDevice : public IPcapDevice {
protected:
    void *m_ShmPtr_;
    size_t m_ShmSize_;

    explicit IShmDevice(void *shmPtr, size_t shmSize)
        : IPcapDevice(), m_ShmPtr_(shmPtr), m_ShmSize_(shmSize) {}

    virtual ~IShmDevice() {
        close();
    }

public:
    /**
     * @return The pointer to the shared memory region.
     */
    void *GetShmPtr() const {
        return m_ShmPtr_;
    }

    /**
     * @return The size of the shared memory region.
     */
    size_t GetShmSize() const {
        return m_ShmSize_;
    }

    void close() {
        if (m_PcapDescriptor != nullptr) {
            m_PcapDescriptor = nullptr;
            // Additional cleanup if needed
        }

        m_DeviceOpened = false;
    }
};

/**
 * @class IShmWriterDevice
 * An abstract class for shared memory writer devices.
 */
class IShmWriterDevice : public IShmDevice {
protected:
    uint32_t m_NumOfPacketsWritten_;
    uint32_t m_NumOfPacketsNotWritten_;

    IShmWriterDevice(void *shmPtr, size_t shmSize)
        : IShmDevice(shmPtr, shmSize), m_NumOfPacketsWritten_(0), m_NumOfPacketsNotWritten_(0) {}

public:
    virtual ~IShmWriterDevice() {}

    /**
     * Write a raw packet to shared memory.
     * @param[in] packet The packet to write.
     * @return True on success, false otherwise.
     */
    virtual bool WritePacket(RawPacket const &packet) = 0;

    /**
     * Write multiple raw packets to shared memory.
     * @param[in] packets Vector of packets to write.
     * @return True on success, false otherwise.
     */
    virtual bool WritePackets(RawPacketVector const &packets) = 0;
};

/**
 * @class PcapShmWriterDevice
 * A class for writing packets to a shared memory region in pcap format.
 */
class PcapShmWriterDevice : public IShmWriterDevice {
private:
    LinkLayerType m_LinkLayerType_;
    FileTimestampPrecision m_Precision_;

    std::vector<FILE *> m_Files_;             // FILE* streams for each segment
    std::vector<pcap_dumper_t *> m_Dumpers_;  // pcap_dumper_t* for each segment
    size_t m_PcapFiles_;                      // Number of pcap segments
    size_t m_CurrentFileIndex_;               // Current segment we are writing to
    size_t m_SegmentSize_;                    // Size of each segment
    // Define the fixed size of the pcap packet header on disk
    // The on-disk pcap packet header consists of:
    // - ts_sec (4 bytes)
    // - ts_usec or ts_nsec (4 bytes)
    // - caplen (4 bytes)
    // - len (4 bytes)
    // Total: 16 bytes
    static constexpr size_t kPcapPacketHeaderSizeOnDisk = 16;
    static constexpr size_t kPcapFileHeaderSize = 24;

    struct SegmentInfo {
        void *startPtr;  // Pointer to the start of this segment
        size_t size;     // Size of the segment
    };

    std::vector<SegmentInfo> m_Segments_;  // Information about each segment

    // Private copy constructor and assignment operator
    PcapShmWriterDevice(PcapShmWriterDevice const &other) = delete;
    PcapShmWriterDevice &operator=(PcapShmWriterDevice const &other) = delete;

    bool RotateToNextSegment(size_t needed) {
        // Move to next segment
        m_CurrentFileIndex_ = (m_CurrentFileIndex_ + 1) % m_PcapFiles_;
        FILE *f = m_Files_[m_CurrentFileIndex_];

        // Reset to just after the global header
        return !fseek(f, kPcapFileHeaderSize, SEEK_SET);
    }

public:
    /**
     * Constructor
     * @param[in] shmPtr Pointer to the shared memory region.
     * @param[in] shmSize Size of the shared memory region.
     * @param[in] pcapFiles Number of pcap files (segments).
     * @param[in] linkLayerType The link layer type all packets in this region will be based on. The
     * default is Ethernet.
     * @param[in] nanosecondsPrecision A boolean indicating whether to write timestamps in
     * nano-precision. If set to false, timestamps will be written in micro-precision.
     */
    PcapShmWriterDevice(void *shmPtr, size_t shmSize, size_t pcapFiles,
                        LinkLayerType linkLayerType = LINKTYPE_ETHERNET,
                        bool nanosecondsPrecision = false)
        : IShmWriterDevice(shmPtr, shmSize),
          m_LinkLayerType_(linkLayerType),
          m_PcapFiles_(pcapFiles),
          m_CurrentFileIndex_(0) {
#if defined(PCAP_TSTAMP_PRECISION_NANO)
        m_Precision_ = nanosecondsPrecision ? FileTimestampPrecision::Nanoseconds
                                            : FileTimestampPrecision::Microseconds;
#else
        if (nanosecondsPrecision) {
            TMP_LOG("PcapPlusPlus was compiled without nano precision support which requires "
                    "libpcap > 1.5.1. Please "
                    "recompile PcapPlusPlus with nano precision support to use this feature. Using "
                    "default microsecond precision");
        }
        m_Precision_ = FileTimestampPrecision::Microseconds;
#endif

        m_SegmentSize_ = m_ShmSize_ / m_PcapFiles_;

        /* if (m_SegmentSize <= 24 + PCPP_MAX_PACKET_SIZE - 1) { */
        /*     TMP_LOG("Segment too small to hold at least one full packet"); */
        /*     throw("something"); */
        /* } */
    }

    /**
     * Destructor
     */
    ~PcapShmWriterDevice() {
        PcapShmWriterDevice::close();
    }

    void DumpPcapFilesToDisk(std::string const &filenamePrefix) {
        // Ensure all data is flushed to memory
        Flush();

        for (size_t i = 0; i < m_PcapFiles_; ++i) {
            FILE *f = m_Files_[i];
            if (f == nullptr) {
                // If file is already closed or not opened, skip
                continue;
            }

            long current_pos = ftell(f);
            if (current_pos < 0) {
                TMP_LOG("ftell failed on segment " << i);
                continue;
            }

            // If only global header (24 bytes) is present, no packets were written
            if (current_pos <= 24) {
                // Skip this segment
                continue;
            }

            size_t used_size = static_cast<size_t>(current_pos);

            std::string filename = filenamePrefix + std::to_string(i + 1) + ".pcap";
            std::ofstream output_file(filename, std::ios::binary);
            if (!output_file) {
                TMP_LOG("Failed to open " << filename << " for writing");
                continue;
            }

            // Write exactly 'usedSize' bytes from the segment to the file
            output_file.write(reinterpret_cast<char *>(m_Segments_[i].startPtr), used_size);
            if (output_file.bad()) {
                TMP_LOG("Error writing to file " << filename);
                continue;
            }

            TMP_LOG("Wrote " << used_size << " bytes to " << filename);
        }
    }

    /**
     * Open the device for writing.
     * @return True if the device was opened successfully, false otherwise.
     */
    bool open() override {
        if (m_DeviceOpened) {
            return true;
        }

        switch (m_LinkLayerType_) {
            case LINKTYPE_RAW:
            case LINKTYPE_DLT_RAW2:
                TMP_LOG("The only Raw IP link type supported in libpcap/WinPcap/Npcap is "
                        "LINKTYPE_DLT_RAW1, please use that instead");
                m_DeviceOpened = false;
                return m_DeviceOpened;
            default:
                break;
        }

        m_NumOfPacketsNotWritten_ = 0;
        m_NumOfPacketsWritten_ = 0;

        m_Segments_.resize(m_PcapFiles_);
        for (size_t i = 0; i < m_PcapFiles_; ++i) {
            m_Segments_[i].startPtr = (uint8_t *)m_ShmPtr_ + i * m_SegmentSize_;
            m_Segments_[i].size = m_SegmentSize_;
        }

        // Open pcap descriptor
#if defined(PCAP_TSTAMP_PRECISION_NANO)
        m_PcapDescriptor = internal::PcapHandle(pcap_open_dead_with_tstamp_precision(
                m_LinkLayerType_, PCPP_MAX_PACKET_SIZE - 1, static_cast<int>(m_Precision_)));
#else
        m_PcapDescriptor =
                internal::PcapHandle(pcap_open_dead(m_LinkLayerType_, PCPP_MAX_PACKET_SIZE - 1));
#endif
        if (m_PcapDescriptor == nullptr) {
            TMP_LOG("Error opening pcap descriptor: pcap_open_dead returned nullptr");
            m_DeviceOpened = false;
            return m_DeviceOpened;
        }

        // Initialize FILE* and pcap_dumper_t* for each segment
        for (size_t i = 0; i < m_PcapFiles_; ++i) {
            FILE *f = fmemopen(m_Segments_[i].startPtr, m_Segments_[i].size, "w+");
            if (!f) {
                TMP_LOG("fmemopen failed for segment " << i);
                m_DeviceOpened = false;
                return m_DeviceOpened;
            }

            pcap_dumper_t *d = pcap_dump_fopen(m_PcapDescriptor.get(), f);
            if (!d) {
                TMP_LOG("pcap_dump_fopen failed for segment " << i);
                m_DeviceOpened = false;
                fclose(f);
                return m_DeviceOpened;
            }

            m_Files_.push_back(f);
            m_Dumpers_.push_back(d);
        }

        m_CurrentFileIndex_ = 0;
        m_DeviceOpened = true;
        return true;
    }

    /**
     * Write a RawPacket to the shared memory.
     */
    bool WritePacket(RawPacket const &packet) override {
        if (!m_DeviceOpened) {
            TMP_LOG("Device not opened");
            m_NumOfPacketsNotWritten_++;
            return false;
        }

        if (packet.getLinkLayerType() != m_LinkLayerType_) {
            TMP_LOG("Cannot write a packet with a different link layer type");
            m_NumOfPacketsNotWritten_++;
            return false;
        }

        // Prepare packet header
        pcap_pkthdr pkt_hdr;
        pkt_hdr.caplen = packet.getRawDataLen();
        pkt_hdr.len = packet.getFrameLength();

        timespec packet_timestamp = packet.getPacketTimeStamp();
#if defined(PCAP_TSTAMP_PRECISION_NANO)
        if (m_Precision_ != FileTimestampPrecision::Nanoseconds) {
            TIMESPEC_TO_TIMEVAL(&pkt_hdr.ts, &packet_timestamp);
        } else {
            pkt_hdr.ts.tv_sec = packet_timestamp.tv_sec;
            pkt_hdr.ts.tv_usec = packet_timestamp.tv_nsec;
        }
#else
        TIMESPEC_TO_TIMEVAL(&pkt_hdr.ts, &packet_timestamp);
#endif

        // Define the fixed size of the pcap packet header on disk
        // The on-disk pcap packet header consists of:
        // - ts_sec (4 bytes)
        // - ts_usec or ts_nsec (4 bytes)
        // - caplen (4 bytes)
        // - len (4 bytes)
        // Total: 16 bytes
        // Estimate the size needed for this packet in the pcap file
        // Note: We use a fixed size for the packet header as it is written to disk,
        // which is independent of the in-memory size of `struct pcap_pkthdr`.
        size_t needed = kPcapPacketHeaderSizeOnDisk + pkt_hdr.caplen;

        FILE *f = m_Files_[m_CurrentFileIndex_];
        long pos = ftell(f);
        if (pos < 0) {
            TMP_LOG("ftell failed on current segment");
            m_NumOfPacketsNotWritten_++;
            return false;
        }

        size_t used = (size_t)pos;
        size_t available = m_SegmentSize_ - used;
        if (needed > available) {
            // Rotate to next segment
            if (!RotateToNextSegment(needed)) {
                TMP_LOG("fseek failed when rotating to next segment");
                m_NumOfPacketsNotWritten_++;
                return false;
            }

            f = m_Files_[m_CurrentFileIndex_];
        }

        // Now write the packet
        pcap_dump((uint8_t *)m_Dumpers_[m_CurrentFileIndex_], &pkt_hdr, packet.getRawData());
        m_NumOfPacketsWritten_++;
        return true;
    }

    /**
     * Write multiple RawPackets to the shared memory.
     */
    bool WritePackets(RawPacketVector const &packets) override {
        for (RawPacket const *packet : packets) {
            if (!WritePacket(*packet)) return false;
        }

        return true;
    }

    /**
     * Flush the shared memory buffer.
     */
    void Flush() {
        if (!m_DeviceOpened) return;

        for (auto d : m_Dumpers_) {
            if (d != nullptr) {
                if (pcap_dump_flush(d) == -1)
                    TMP_LOG("Error while flushing the packets to shared memory");
            }
        }

        for (auto f : m_Files_) {
            if (f != nullptr) {
                if (fflush(f) == EOF) TMP_LOG("Error while flushing the packets to file");
            }
        }
    }

    /**
     * Close the device.
     */
    void close() override {
        if (!m_DeviceOpened) return;

        Flush();

        for (size_t i = 0; i < m_PcapFiles_; i++) {
            if (m_Dumpers_[i] != nullptr) {
                pcap_dump_close(m_Dumpers_[i]);  // This also closes the associated FILE*
                m_Dumpers_[i] = nullptr;
                m_Files_[i] = nullptr;  // Already closed by pcap_dump_close
            }
        }

        m_PcapDescriptor = nullptr;
        m_DeviceOpened = false;
    }

    /**
     * Get statistics of packets written so far.
     */
    void getStatistics(PcapStats &stats) const override {
        stats.packetsRecv = m_NumOfPacketsWritten_;
        stats.packetsDrop = m_NumOfPacketsNotWritten_;
        stats.packetsDropByInterface = 0;
    }
};

}  // namespace pcpp
