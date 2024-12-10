#pragma once

#include <cstdio>
#include <fstream>
#include <iostream>
#include <pcap/pcap.h>
#include <vector>

#include "PcapDevice.h"
#include "PcapFileDevice.h"

// The PcapPlus Plus namespace.
namespace pcpp {

/**
 * @brief An abstract class representing a shared memory device for pcap data.
 *
 * This device provides a pcap-compatible interface for reading/writing packets,
 * but the underlying storage is a shared memory region rather than a file or a live network
 * interface.
 *
 * Derived classes must implement device-specific logic for reading/writing packets.
 */
class IShmDevice : public IPcapDevice {
protected:
    void *shm_ptr_;
    size_t shm_size_;

    explicit IShmDevice(void *shm_ptr, size_t shm_size)
        : IPcapDevice(), shm_ptr_(shm_ptr), shm_size_(shm_size) {}

    ~IShmDevice() override {
        close();
    }

public:
    /**
     * @return Pointer to the underlying shared memory region.
     */
    [[nodiscard]] void *GetShmPtr() const {
        return shm_ptr_;
    }

    /**
     * @return The size of the shared memory region in bytes.
     */
    [[nodiscard]] size_t GetShmSize() const {
        return shm_size_;
    }

    /**
     * @brief Close the device.
     *
     * This will release any pcap resources associated with it.
     */
    void close() override {
        if (m_PcapDescriptor != nullptr) {
            m_PcapDescriptor = nullptr;
        }
        m_DeviceOpened = false;
    }
};

/**
 * @brief An abstract class for shared memory writer devices.
 *
 * A writer device provides methods to write packets into the shared memory region.
 * These packets can later be read or dumped to disk by other utilities.
 */
class IShmWriterDevice : public IShmDevice {
protected:
    uint32_t num_of_packets_written_;
    uint32_t num_of_packets_not_written_;

    IShmWriterDevice(void *shm_ptr, size_t shm_size)
        : IShmDevice(shm_ptr, shm_size),
          num_of_packets_written_(0),
          num_of_packets_not_written_(0) {}

public:
    ~IShmWriterDevice() override = default;

    /**
     * @brief Write a single RawPacket into the shared memory.
     *
     * @param[in] packet The packet to write.
     *
     * @return True if the packet was written successfully, false otherwise.
     */
    [[nodiscard]] virtual bool WritePacket(RawPacket const &packet) = 0;

    /**
     * @brief Write multiple RawPackets into the shared memory.
     *
     * @param[in] packets A vector of packet pointers to be written.
     *
     * @return True if all packets were written successfully, false otherwise.
     */
    [[nodiscard]] virtual bool WritePackets(RawPacketVector const &packets) = 0;
};

/**
 * @brief A class for writing packets to a shared memory region in pcap format, using a ring-buffer
 * approach.
 *
 * The objective is to enable continuous packet capture while utilizing a limited amount of memory.
 * The approach adopted here is inspired by Wireshark's "multiple files, ring buffer" feature:
 *
 * Multiple files, ring buffer:
 * "Much like 'Multiple files continuous', reaching one of the multiple files switch conditions
 * (one of the 'Next file every …' values) will switch to the next file. This will be a newly
 * created file if the value of 'Ring buffer with n files' is not reached; otherwise, it will
 * replace the oldest of the formerly used files (thus forming a 'ring').
 *
 * This mode will limit the maximum disk usage, even for an unlimited amount of capture input data,
 * only keeping the latest captured data."
 * (Source: https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureFiles.html)
 *
 * **Algorithm Behind Ring-Buffer Writing:**
 * The shared memory region is divided into multiple segments (each representing a 'virtual pcap
 * file'). Packets are written sequentially into the current segment. If there isn't enough space
 * for a new packet, the writer 'rotates' to the next segment.
 * - Suppose you have N segments.
 * - You write packets into segment 1 until it's almost full.
 * - If you can't fit a new packet, you move to segment 2, and continue writing there.
 * - Once you reach segment N and still have more packets, you wrap around to segment 1 again,
 *   overwriting old data.
 *
 * After all packets are written, `DumpPcapFilesToDisk()` can be used to extract each segment
 * into a standalone pcap file.
 */
class PcapShmWriterDevice : public IShmWriterDevice {
    LinkLayerType link_layer_type_;
    FileTimestampPrecision precision_;

    size_t pcap_files_;             ///< Number of pcap segments
    size_t current_segment_index_;  ///< Current segment index we're writing to

    static constexpr size_t kPcapPacketHeaderSizeOnDisk = 16;
    static constexpr size_t kPcapFileHeaderSize = 24;

    struct SegmentInfo {
        void *start_ptr;        ///< Pointer to the start of this segment in shared memory
        size_t size;            ///< Size of the segment
        FILE *file;             ///< FILE stream for this pcap segment
        pcap_dumper_t *dumper;  ///< pcap dumper for this pcap segment
    };

    std::vector<SegmentInfo> segments_;

    // Prevent copying
    PcapShmWriterDevice(PcapShmWriterDevice const &) = delete;
    PcapShmWriterDevice &operator=(PcapShmWriterDevice const &) = delete;

    /**
     * @brief Rotate to the next segment if the current one doesn't have enough space.
     *
     * @return True if successful, false if fseek fails.
     */
    bool RotateToNextSegment() {
        current_segment_index_ = (current_segment_index_ + 1) % pcap_files_;
        FILE *file = segments_[current_segment_index_].file;
        // Move file pointer to just after the global header in the new segment
        return (fseek(file, kPcapFileHeaderSize, SEEK_SET) == 0);
    }

    /**
     * @brief Distribute the shared memory into multiple segments and initialize them as in-memory
     * pcap 'files'.
     *
     * This method divides the shared memory region into pcap_files_ segments,
     * ensuring all available memory is utilized. Each segment will have an equal base size,
     * except for the last segment which includes any remainder bytes. It then opens each segment as
     * an in-memory pcap 'file'.
     *
     * @return True if all segments were successfully initialized, false otherwise.
     */
    bool FillSegments() {
        segments_.resize(pcap_files_);

        size_t base_size = shm_size_ / pcap_files_;
        size_t remainder = shm_size_ % pcap_files_;

        size_t offset = 0;
        for (size_t i = 0; i < pcap_files_; ++i) {
            size_t segment_size = base_size + (i == pcap_files_ - 1 ? remainder : 0);
            segments_[i].start_ptr = static_cast<uint8_t *>(shm_ptr_) + offset;
            segments_[i].size = segment_size;
            offset += segment_size;

            FILE *file = fmemopen(segments_[i].start_ptr, segments_[i].size, "w+");
            if (!file) {
                std::cerr << "fmemopen failed for segment " << i << std::endl;
                return false;
            }

            pcap_dumper_t *dumper = pcap_dump_fopen(m_PcapDescriptor.get(), file);
            if (!dumper) {
                std::cerr << "pcap_dump_fopen failed for segment " << i << std::endl;
                fclose(file);
                return false;
            }

            segments_[i].file = file;
            segments_[i].dumper = dumper;
        }

        return true;
    }

public:
    /**
     * @brief Constructor for PcapShmWriterDevice
     *
     * @param[in] shmPtr Pointer to the shared memory region.
     * @param[in] shmSize Size of the shared memory region.
     * @param[in] pcapFiles Number of 'pcap segments' to divide the shared memory into.
     * @param[in] linkLayerType The link layer type all packets in this region will be based on. The
     * default is Ethernet.
     * @param[in] nanosecondsPrecision A boolean indicating whether to write timestamps in
     * nano-precision. If set to false, timestamps will be written in micro-precision.
     */
    PcapShmWriterDevice(void *shm_ptr, size_t shm_size, size_t pcap_files,
                        LinkLayerType link_layer_type = LINKTYPE_ETHERNET,
                        bool nanoseconds_precision = false)
        : IShmWriterDevice(shm_ptr, shm_size),
          link_layer_type_(link_layer_type),
          pcap_files_(pcap_files),
          current_segment_index_(0) {
#if defined(PCAP_TSTAMP_PRECISION_NANO)
        precision_ = nanoseconds_precision ? FileTimestampPrecision::Nanoseconds
                                           : FileTimestampPrecision::Microseconds;
#else
        if (nanosecondsPrecision) {
            std::cerr << "PcapPlusPlus was compiled without nano precision support which requires "
                         "libpcap > 1.5.1. Please "
                         "recompile PcapPlusPlus with nano precision support to use this feature. "
                         "Using "
                         "default microsecond precision.\n";
        }
        m_Precision_ = FileTimestampPrecision::Microseconds;
#endif

        // TODO: we should add this assert
        /* if (m_SegmentSize <= kPcapFileHeaderSize + PCPP_MAX_PACKET_SIZE - 1) { */
        /*     TMP_LOG("Segment too small to hold at least one full packet"); */
        /*     throw("something"); */
        /* } */
    }

    ~PcapShmWriterDevice() override {
        PcapShmWriterDevice::close();
    }

    /**
     * @brief Dump each pcap segment from shared memory to a file on disk.
     *
     * @param filenamePrefix The prefix for the output pcap files, e.g. "capture_"
     *        will produce "capture_1.pcap", "capture_2.pcap", etc.
     */
    void DumpPcapFilesToDisk(std::string_view filename_prefix) {
        Flush();

        size_t file_index = 1;
        std::string filename;
        // Allocate space for prefix + index + ".pcap"
        filename.reserve(filename_prefix.size() + 10);

        for (size_t i = 0; i < pcap_files_; ++i) {
            size_t segment_index = (current_segment_index_ + 1 + i) % pcap_files_;
            FILE *file = segments_[segment_index].file;

            // Not opened or already closed
            if (file == nullptr) {
                continue;
            }

            size_t used = ftell(file);
            if (used < 0) {
                std::cerr << "ftell failed on segment " << i << std::endl;
                continue;
            }

            // If only global header is present, no packets were written.
            if (used <= kPcapFileHeaderSize) {
                continue;
            }

            filename = filename_prefix;
            filename += std::to_string(file_index++) + ".pcap";
            std::ofstream output_file(filename, std::ios::binary);
            if (!output_file) {
                std::cerr << "Failed to open " << filename << " for writing" << std::endl;
                continue;
            }

            output_file.write(reinterpret_cast<char *>(segments_[segment_index].start_ptr), used);
            if (output_file.bad()) {
                std::cerr << "Error writing to file " << filename << std::endl;
                continue;
            }
        }
    }

    bool open() override {
        if (m_DeviceOpened) {
            return true;
        }

        switch (link_layer_type_) {
            case LINKTYPE_RAW:
            case LINKTYPE_DLT_RAW2:
                std::cerr << "The only Raw IP link type supported in libpcap/WinPcap/Npcap is "
                             "LINKTYPE_DLT_RAW1, please use that instead\n";
                return false;
            default:
                break;
        }

#if defined(PCAP_TSTAMP_PRECISION_NANO)
        m_PcapDescriptor = internal::PcapHandle(pcap_open_dead_with_tstamp_precision(
                link_layer_type_, PCPP_MAX_PACKET_SIZE - 1, static_cast<int>(precision_)));
#else
        m_PcapDescriptor =
                internal::PcapHandle(pcap_open_dead(m_LinkLayerType_, PCPP_MAX_PACKET_SIZE - 1));
#endif
        if (m_PcapDescriptor == nullptr) {
            std::cerr << "Error opening pcap descriptor: pcap_open_dead returned nullptr"
                      << std::endl;
            return false;
        }

        if (!FillSegments()) {
            return false;
        }

        current_segment_index_ = 0;
        m_DeviceOpened = true;
        return true;
    }

    bool WritePacket(RawPacket const &packet) override {
        if (!m_DeviceOpened) {
            std::cerr << "Device not opened" << std::endl;
            ++num_of_packets_not_written_;
            return false;
        }

        if (packet.getLinkLayerType() != link_layer_type_) {
            std::cerr << "Cannot write a packet with a different link layer type" << std::endl;
            ++num_of_packets_not_written_;
            return false;
        }

        pcap_pkthdr pkt_hdr;
        pkt_hdr.caplen = packet.getRawDataLen();
        pkt_hdr.len = packet.getFrameLength();

        timespec packet_timestamp = packet.getPacketTimeStamp();
#if defined(PCAP_TSTAMP_PRECISION_NANO)
        if (precision_ != FileTimestampPrecision::Nanoseconds) {
            TIMESPEC_TO_TIMEVAL(&pkt_hdr.ts, &packet_timestamp);
        } else {
            pkt_hdr.ts.tv_sec = packet_timestamp.tv_sec;
            pkt_hdr.ts.tv_usec = packet_timestamp.tv_nsec;
        }
#else
        TIMESPEC_TO_TIMEVAL(&pkt_hdr.ts, &packet_timestamp);
#endif

        // kPcapPacketHeaderSizeOnDisk is different from sizeof(pcap_pkthdr)
        size_t needed = kPcapPacketHeaderSizeOnDisk + pkt_hdr.caplen;

        FILE *file = segments_[current_segment_index_].file;
        size_t used = ftell(file);
        if (used < 0) {
            std::cerr << "ftell failed on current segment" << std::endl;
            ++num_of_packets_not_written_;
            return false;
        }

        size_t available = segments_[current_segment_index_].size - used;
        if (needed > available) {
            if (!RotateToNextSegment()) {
                std::cerr << "fseek failed when rotating to next segment" << std::endl;
                ++num_of_packets_not_written_;
                return false;
            }
            file = segments_[current_segment_index_].file;
        }

        pcap_dump(reinterpret_cast<uint8_t *>(segments_[current_segment_index_].dumper), &pkt_hdr,
                  packet.getRawData());
        ++num_of_packets_written_;
        return true;
    }

    bool WritePackets(RawPacketVector const &packets) override {
        for (RawPacket const *packet : packets) {
            if (!WritePacket(*packet)) return false;
        }
        return true;
    }

    /**
     * @brief Flush all pending writes to the shared memory segments.
     */
    void Flush() {
        if (!m_DeviceOpened) return;

        for (auto &seg : segments_) {
            if (seg.dumper != nullptr && pcap_dump_flush(seg.dumper) == -1) {
                std::cerr << "Error while flushing the packets to shared memory" << std::endl;
            }
        }

        for (auto &seg : segments_) {
            if (seg.file != nullptr && fflush(seg.file) == EOF) {
                std::cerr << "Error while flushing the packets to file" << std::endl;
            }
        }
    }

    /**
     * @brief Close the device and free associated resources.
     */
    void close() override {
        if (!m_DeviceOpened) return;

        Flush();

        for (auto &[ptr, size, file, dumper] : segments_) {
            if (dumper != nullptr) {
                // pcap_dump_close closes both the dumper and the FILE*
                pcap_dump_close(dumper);
                ptr = nullptr;
                size = 0;
                dumper = nullptr;
                file = nullptr;
            }
        }

        m_PcapDescriptor.reset();
        m_DeviceOpened = false;
    }

    /**
     * @brief Get statistics for packets written so far.
     *
     * @param[out] stats The PcapStats structure to fill.
     */
    void getStatistics(PcapStats &stats) const override {
        stats.packetsRecv = num_of_packets_written_;
        stats.packetsDrop = num_of_packets_not_written_;
        stats.packetsDropByInterface = 0;
    }
};

}  // namespace pcpp
