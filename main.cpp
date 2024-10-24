#include <Packet.h>
#include <PcapFileDevice.h>
#include <RawPacket.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared_memory.h"

std::string Hexdump(std::string_view data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    size_t const size = data.size();

    for (size_t offset = 0; offset < size; offset += 16) {
        oss << std::setw(8) << offset << "  ";

        std::string ascii_representation;
        ascii_representation.reserve(16);

        size_t const line_size = std::min(size - offset, size_t(16));

        for (size_t i = 0; i < 16; ++i) {
            if (i == 8) {
                oss << "  ";
            } else if (i != 0) {
                oss << ' ';
            }

            if (i < line_size) {
                auto const byte = static_cast<unsigned char>(data[offset + i]);
                oss << std::setw(2) << static_cast<int>(byte);

                ascii_representation += std::isprint(byte) ? byte : '.';
            } else {
                oss << "  ";
                ascii_representation += ' ';
            }
        }

        oss << "  |" << ascii_representation << "|\n";
    }

    return oss.str();
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    std::string_view pcap_file_name = argv[1];

    constexpr std::string_view shm_name = "/my_shared_memory";
    constexpr size_t shm_size = 10 * 1024 * 1024;  // 10 MB

    try {
        SharedMemory shm(shm_name, shm_size);

        // Write "hello world" to shared memory
        constexpr std::string_view message = "hello world";
        std::memcpy(shm.Get(), message.data(), message.size());
        // Hexdump the written content
        std::string_view data_view(reinterpret_cast<char const *>(shm.Get()), message.size());
        std::string dump = Hexdump(data_view);

        std::cout << "Hexdump of shared memory content:" << std::endl;
        std::cout << dump << std::endl;

        // Open the pcap file
        std::unique_ptr<pcpp::IFileReaderDevice> reader(
                pcpp::IFileReaderDevice::getReader(std::string(pcap_file_name)));

        if (!reader->open()) {
            std::cerr << "Error opening the pcap file" << std::endl;
            return 1;
        }

        // Read and print packets
        pcpp::RawPacket raw_packet;
        while (reader->getNextPacket(raw_packet)) {
            pcpp::Packet parsed_packet(&raw_packet);
            std::cout << parsed_packet.toString() << std::endl;
        }

        reader->close();
    } catch (std::system_error const &e) {
        std::cerr << "System error: " << e.what() << std::endl;
        return 1;
    } catch (std::exception const &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
