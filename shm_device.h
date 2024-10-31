#pragma once

#include <array>  // For std::array
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
    static constexpr size_t kMaxPcapFiles = 10;         // Maximum number of pcap files (segments)
    size_t m_PcapFiles_;                                // Actual number of pcap files
    size_t m_SegmentSize_;                              // Size of each segment
    std::array<void *, kMaxPcapFiles> m_SegmentPtrs_;   // Pointers to each segment
    std::array<size_t, kMaxPcapFiles> m_SegmentSizes_;  // Sizes of data written in each segment
    size_t m_CurrentSegment_;                           // Index of current segment
    LinkLayerType m_LinkLayerType_;
    FileTimestampPrecision m_Precision_;
    pcap_dumper_t *m_PcapDumpHandler_;  // Current pcap dumper
    FILE *m_File_;                      // Current FILE* stream

    // Private copy constructor and assignment operator
    PcapShmWriterDevice(PcapShmWriterDevice const &other) = delete;
    PcapShmWriterDevice &operator=(PcapShmWriterDevice const &other) = delete;

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
          m_PcapFiles_(pcapFiles),
          m_SegmentSize_(0),
          m_SegmentPtrs_(),
          m_SegmentSizes_(),
          m_CurrentSegment_(0),
          m_LinkLayerType_(linkLayerType),
          m_PcapDumpHandler_(nullptr),
          m_File_(nullptr) {
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
        if (m_PcapFiles_ > kMaxPcapFiles) {
            throw std::invalid_argument("pcapFiles exceeds kMaxPcapFiles");
        }
    }

    /**
     * Destructor
     */
    ~PcapShmWriterDevice() {
        PcapShmWriterDevice::close();
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
                return false;
            default:
                break;
        }

        m_NumOfPacketsNotWritten_ = 0;
        m_NumOfPacketsWritten_ = 0;

        // Initialize segments
        m_SegmentSize_ = m_ShmSize_ / m_PcapFiles_;
        for (size_t i = 0; i < m_PcapFiles_; ++i) {
            m_SegmentPtrs_[i] = static_cast<char *>(m_ShmPtr_) + i * m_SegmentSize_;
            m_SegmentSizes_[i] = 0;
        }

        m_CurrentSegment_ = 0;

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
            return false;
        }

        // Open the first segment
        m_File_ = fmemopen(m_SegmentPtrs_[m_CurrentSegment_], m_SegmentSize_, "wb+");
        if (m_File_ == nullptr) {
            TMP_LOG("Failed to open shared memory as FILE* using fmemopen");
            m_DeviceOpened = false;
            return false;
        }

        // Get pcap dump handler using pcap_dump_fopen
        m_PcapDumpHandler_ = pcap_dump_fopen(m_PcapDescriptor.get(), m_File_);
        if (m_PcapDumpHandler_ == nullptr) {
            TMP_LOG("Error opening pcap dump handler: pcap_dump_fopen returned nullptr");
            m_DeviceOpened = false;
            return false;
        }

        // Set initial segment size (pcap global header size)
        m_SegmentSizes_[m_CurrentSegment_] = sizeof(pcap_file_header);

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
        constexpr size_t pcap_packet_header_size_on_disk = 16;

        // Estimate the size needed for this packet in the pcap file
        // Note: We use a fixed size for the packet header as it is written to disk,
        // which is independent of the in-memory size of `struct pcap_pkthdr`.
        size_t estimated_size = pcap_packet_header_size_on_disk + pkt_hdr.caplen;

        if (m_SegmentSizes_[m_CurrentSegment_] + estimated_size > m_SegmentSize_) {
            // Close current pcap dumper
            pcap_dump_close(m_PcapDumpHandler_);  // This will also close m_File_

            // Advance to next segment
            m_CurrentSegment_ = (m_CurrentSegment_ + 1) % m_PcapFiles_;

            // Reset the segment
            m_SegmentSizes_[m_CurrentSegment_] = 0;

            // Open new FILE* for the segment
            m_File_ = fmemopen(m_SegmentPtrs_[m_CurrentSegment_], m_SegmentSize_, "wb+");
            if (m_File_ == nullptr) {
                TMP_LOG("Failed to open shared memory as FILE* using fmemopen");
                m_NumOfPacketsNotWritten_++;
                return false;
            }

            // Open new pcap dumper
            m_PcapDumpHandler_ = pcap_dump_fopen(m_PcapDescriptor.get(), m_File_);
            if (m_PcapDumpHandler_ == nullptr) {
                TMP_LOG("Error opening pcap dump handler: pcap_dump_fopen returned nullptr");
                m_NumOfPacketsNotWritten_++;
                return false;
            }

            // The pcap global header will be written again
            m_SegmentSizes_[m_CurrentSegment_] = sizeof(pcap_file_header);
        }

        // Write the packet using libpcap's pcap_dump
        pcap_dump((uint8_t *)m_PcapDumpHandler_, &pkt_hdr, packet.getRawData());

        // Update segment size
        m_SegmentSizes_[m_CurrentSegment_] += estimated_size;

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

        if (pcap_dump_flush(m_PcapDumpHandler_) == -1) {
            TMP_LOG("Error while flushing the packets to shared memory");
        }

        if (fflush(m_File_) == EOF) {
            TMP_LOG("Error while flushing the packets to file");
        }
    }

    /**
     * Close the device.
     */
    void close() override {
        if (!m_DeviceOpened) return;

        Flush();

        // Close current pcap dumper
        if (m_PcapDumpHandler_ != nullptr) {
            pcap_dump_close(m_PcapDumpHandler_);  // Closes m_File_ too
            m_PcapDumpHandler_ = nullptr;
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

    /**
     * Get the pointer to a specific segment.
     */
    void *GetSegmentPtr(size_t index) const {
        if (index >= m_PcapFiles_) return nullptr;
        return m_SegmentPtrs_[index];
    }

    /**
     * Get the size of data written in a specific segment.
     */
    size_t GetSegmentSize(size_t index) const {
        if (index >= m_PcapFiles_) return 0;
        return m_SegmentSizes_[index];
    }
};

}  // namespace pcpp
