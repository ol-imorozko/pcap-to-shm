// IShmDevice.h

#pragma once

#include <pcap/pcap.h>

#include "Logger.h"
#include "PcapDevice.h"
#include "PcapFileDevice.h"

namespace pcpp {
/**
 * @class IShmDevice
 * An abstract class representing a shared memory device.
 * This class is abstract and cannot be instantiated.
 */
class IShmDevice : public IPcapDevice {
protected:
    void* m_ShmPtr_;
    size_t m_ShmSize_;

    explicit IShmDevice(void* shmPtr, size_t shmSize)
        : IPcapDevice(), m_ShmPtr_(shmPtr), m_ShmSize_(shmSize) {}

    // Pure virtual destructor, we don't have a specific close method
    // due to shared memory being managed by other means
    virtual ~IShmDevice() {
        close();
    }

public:
    /**
     * @return The pointer to the shared memory region.
     */
    void* GetShmPtr() const {
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
            // FIXME:
            PCPP_LOG(pcpp::Logger::Debug, "Successfully closed file reader device for shared memory '"
                           << "0xTMP,ADDLOGGING" << "'");
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

    IShmWriterDevice(void* shmPtr, size_t shmSize)
        : IShmDevice(shmPtr, shmSize), m_NumOfPacketsWritten_(0), m_NumOfPacketsNotWritten_(0) {}

public:
    static constexpr size_t kGlobalPcapHeaderSize = 24;
    static constexpr size_t kPacketPcapHeaderSize = 16;

    virtual ~IShmWriterDevice() {}

    /**
     * Write a raw packet to shared memory.
     * @param[in] packet The packet to write.
     * @return True on success, false otherwise.
     */
    virtual bool WritePacket(RawPacket const& packet) = 0;

    /**
     * Write multiple raw packets to shared memory.
     * @param[in] packets Vector of packets to write.
     * @return True on success, false otherwise.
     */
    virtual bool WritePackets(RawPacketVector const& packets) = 0;

    // We don't need an open() method since shared memory is provided externally
};

/**
 * @class PcapShmWriterDevice
 * A class for writing packets to a shared memory region in pcap format.
 * Utilizes libpcap functions and writes to shared memory via a FILE* stream obtained from fmemopen.
 */
class PcapShmWriterDevice : public IShmWriterDevice {
private:
    size_t m_CurrentOffset_;  // Current write offset in the shared memory
    LinkLayerType m_LinkLayerType_;
    FileTimestampPrecision m_Precision_;
    pcap_dumper_t* m_PcapDumpHandler_;
    FILE* m_File_;

    // Private copy constructor and assignment operator
    PcapShmWriterDevice(PcapShmWriterDevice const& other);
    PcapShmWriterDevice& operator=(PcapShmWriterDevice const& other);

public:
    /**
     * Constructor
     * @param[in] shmPtr Pointer to the shared memory region.
     * @param[in] shmSize Size of the shared memory region.
     * @param[in] linkLayerType The link layer type all packets in this region will be based on. The
     * default is Ethernet.
     * @param[in] nanosecondsPrecision A boolean indicating whether to write timestamps in
     * nano-precision. If set to false, timestamps will be written in micro-precision.
     */
    PcapShmWriterDevice(void* shmPtr, size_t shmSize,
                        LinkLayerType linkLayerType = LINKTYPE_ETHERNET,
                        bool nanosecondsPrecision = false)
        : IShmWriterDevice(shmPtr, shmSize),
          m_CurrentOffset_(0),
          m_LinkLayerType_(linkLayerType),
          m_PcapDumpHandler_(nullptr),
          m_File_(nullptr) {
#if defined(PCAP_TSTAMP_PRECISION_NANO)
        m_Precision_ = nanosecondsPrecision ? FileTimestampPrecision::Nanoseconds
                                            : FileTimestampPrecision::Microseconds;
#else
        if (nanosecondsPrecision) {
            PCPP_LOG_ERROR(
                    "PcapPlusPlus was compiled without nano precision support which requires "
                    "libpcap > 1.5.1. Please "
                    "recompile PcapPlusPlus with nano precision support to use this feature. Using "
                    "default microsecond precision");
        }
        m_Precision = FileTimestampPrecision::Microseconds;
#endif
        PCPP_LOG(pcpp::Logger::Debug, "Constructed.");
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
            PCPP_LOG(pcpp::Logger::Debug, "Device already opened. Nothing to do");
            return true;
        }

        switch (m_LinkLayerType_) {
            case LINKTYPE_RAW:
            case LINKTYPE_DLT_RAW2:
                PCPP_LOG_ERROR(
                        "The only Raw IP link type supported in libpcap/WinPcap/Npcap is "
                        "LINKTYPE_DLT_RAW1, please use that instead");
                return false;
            default:
                break;
        }

        m_NumOfPacketsNotWritten_ = 0;
        m_NumOfPacketsWritten_ = 0;

        // Open pcap descriptor
#if defined(PCAP_TSTAMP_PRECISION_NANO)
        auto pcap_descriptor = internal::PcapHandle(pcap_open_dead_with_tstamp_precision(
                m_LinkLayerType_, PCPP_MAX_PACKET_SIZE, static_cast<int>(m_Precision_)));
#else
        auto pcap_descriptor =
                internal::PcapHandle(pcap_open_dead(m_LinkLayerType_, PCPP_MAX_PACKET_SIZE));
#endif
        if (pcap_descriptor == nullptr) {
            PCPP_LOG_ERROR("Error opening pcap descriptor: pcap_open_dead returned nullptr");
            m_DeviceOpened = false;
            return false;
        }

        // Use fmemopen to open shared memory as a FILE*
        m_File_ = fmemopen(m_ShmPtr_, m_ShmSize_, "wb+");
        if (m_File_ == nullptr) {
            PCPP_LOG_ERROR("Failed to open shared memory as FILE* using fmemopen");
            m_DeviceOpened = false;
            return false;
        }

        // Get pcap dump handler using pcap_dump_fopen
        m_PcapDumpHandler_ = pcap_dump_fopen(pcap_descriptor.get(), m_File_);
        if (m_PcapDumpHandler_ == nullptr) {
            PCPP_LOG_ERROR("Error opening pcap dump handler: pcap_dump_fopen returned nullptr");
            m_DeviceOpened = false;
            return false;
        }

        m_PcapDescriptor = std::move(pcap_descriptor);
        m_DeviceOpened = true;
        PCPP_LOG(pcpp::Logger::Debug, "Shared memory writer device opened successfully");
        return true;
    }

    /**
     * Write a RawPacket to the shared memory. Before using this method, please verify the device is
     * opened using open(). This method won't change the written packet.
     * @param[in] packet A reference to an existing RawPacket to write to the shared memory.
     * @return True if the packet was written successfully. False will be returned if the device
     * isn't opened or if the packet link layer type is different than the one defined for the
     * device.
     */
    bool WritePacket(RawPacket const& packet) override {
        if (!m_DeviceOpened) {
            PCPP_LOG_ERROR("Device not opened");
            m_NumOfPacketsNotWritten_++;
            return false;
        }

        if (packet.getLinkLayerType() != m_LinkLayerType_) {
            PCPP_LOG_ERROR("Cannot write a packet with a different link layer type");
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
        TIMESPEC_TO_TIMEVAL(&pktHdr.ts, &packet_timestamp);
#endif

        // Before writing, check if there is enough space in the shared memory
        // Get the current position
        long current_pos = ftell(m_File_);
        if (current_pos == -1) {
            PCPP_LOG_ERROR("Failed to get current position in shared memory stream");
            m_NumOfPacketsNotWritten_++;
            return false;
        }

        // Estimate the size needed for this packet
        size_t estimated_size = sizeof(pcap_pkthdr) + pkt_hdr.caplen;

        if (static_cast<size_t>(current_pos) + estimated_size > m_ShmSize_) {
            PCPP_LOG_ERROR("Shared memory overflow while writing packet");
            // You can throw an exception or handle it as needed
            throw std::runtime_error("Shared memory overflow");
            // Alternatively:
            // m_NumOfPacketsNotWritten++;
            // return false;
        }

        // Write the packet using libpcap's pcap_dump
        pcap_dump((uint8_t*)m_PcapDumpHandler_, &pkt_hdr, packet.getRawData());

        m_NumOfPacketsWritten_++;
        PCPP_LOG(pcpp::Logger::Debug, "Packet written successfully to shared memory");
        return true;
    }

    /**
     * Write multiple RawPackets to the shared memory. Before using this method, please verify the
     * device is opened using open(). This method won't change the written packets or the
     * RawPacketVector instance.
     * @param[in] packets A reference to an existing RawPacketVector; all of its packets will be
     * written to the shared memory.
     * @return True if all packets were written successfully to the shared memory. False will be
     * returned if the device isn't opened or if at least one of the packets wasn't written
     * successfully to the shared memory.
     */
    bool WritePackets(RawPacketVector const& packets) override {
        for (RawPacket const* packet : packets) {
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
            PCPP_LOG_ERROR("Error while flushing the packets to shared memory");
        }

        if (fflush(m_File_) == EOF) {
            PCPP_LOG_ERROR("Error while flushing the packets to file");
        }
    }

    /**
     * Close the device.
     */
    void close() override {
        if (!m_DeviceOpened) return;

        Flush();

        // Maybe this should clear shared memory fully? Idk.
        IShmDevice::close();

        if (m_PcapDumpHandler_ != nullptr) {
            pcap_dump_close(m_PcapDumpHandler_);  // closes m_File_ too
        }

        m_PcapDumpHandler_ = nullptr;
        PCPP_LOG(pcpp::Logger::Debug, "Shared memory writer device closed");
    }

    /**
     * Get statistics of packets written so far.
     * @param[out] stats The stats struct where stats are returned.
     */
    void getStatistics(PcapStats& stats) const override {
        stats.packetsRecv = m_NumOfPacketsWritten_;
        stats.packetsDrop = m_NumOfPacketsNotWritten_;
        stats.packetsDropByInterface = 0;
        PCPP_LOG(pcpp::Logger::Debug, "Statistics retrieved for shared memory writer device");
    }
};

}  // namespace pcpp
