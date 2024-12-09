#include <Packet.h>
#include <PcapFileDevice.h>
#include <RawPacket.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>  // Added for file operations
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared_memory.h"
#include "shm_device.h"

// Hexdump function remains the same
std::string Hexdump(std::string_view data) {
    // ... [Function implementation remains unchanged]
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
    // Ensure the program receives exactly two arguments: <pcap_file> and <iteration_number>
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file> <iteration_number>" << std::endl;
        return 1;
    }

    std::string_view pcap_file_name = argv[1];

    // Parse the second argument as an integer representing the iteration number
    int iteration_number;
    try {
        iteration_number = std::stoi(argv[2]);
    } catch (std::invalid_argument const &e) {
        std::cerr << "Invalid iteration number: " << argv[2] << std::endl;
        return 1;
    } catch (std::out_of_range const &e) {
        std::cerr << "Iteration number out of range: " << argv[2] << std::endl;
        return 1;
    }

    constexpr std::string_view shm_name = "/my_shared_memory";
    constexpr size_t shm_size = 30 * 1024;  // 30 Kb
    constexpr size_t pcap_files = 3;        // 3 pcap files

    // Define the path to the CSV file
    std::string const csv_file_path = "result.csv";

    // Check if the CSV file already exists and is non-empty
    bool write_header = false;
    if (!std::filesystem::exists(csv_file_path)) {
        write_header = true;  // File does not exist; need to write header
    } else {
        // Check if the file is empty
        std::ifstream infile(csv_file_path, std::ios::binary | std::ios::ate);
        if (infile.tellg() == 0) {
            write_header = true;  // File exists but is empty; write header
        }
    }

    // Open the CSV file in append mode
    std::ofstream csv_file(csv_file_path, std::ios::out | std::ios::app);
    if (!csv_file.is_open()) {
        std::cerr << "Failed to open " << csv_file_path << " for writing" << std::endl;
        return 1;
    }

    // Write the CSV header if needed
    if (write_header) {
        csv_file << "format,iteration,packet,time_ns\n";
    }

    try {
        SharedMemory shm(shm_name, shm_size);

        // Write "hello world" to shared memory (optional)
        /* constexpr std::string_view message = "hello world"; */
        /* std::memcpy(shm.Get(), message.data(), message.size()); */

        // Hexdump the written content (optional)
        /* std::string_view data_view(reinterpret_cast<char const *>(shm.Get()), message.size()); */
        /* std::string dump = Hexdump(data_view); */

        /* std::cout << "Hexdump of shared memory content:" << std::endl; */
        /* std::cout << dump << std::endl; */

        // Open the pcap file using PcapPlusPlus's IFileReaderDevice
        std::unique_ptr<pcpp::IFileReaderDevice> reader(
                pcpp::IFileReaderDevice::getReader(std::string(pcap_file_name)));

        if (!reader->open()) {
            std::cerr << "Error opening the pcap file: " << pcap_file_name << std::endl;
            return 1;
        }

        // Initialize the shared memory writer with ring buffer functionality
        pcpp::PcapShmWriterDevice shm_writer(shm.Get(), shm.Size(), pcap_files);

        // Try to open the device for writing
        if (!shm_writer.open()) {
            std::cerr << "Cannot open shared memory for writing" << std::endl;
            return 1;
        }

        // Initialize packet counter
        size_t packet_number = 0;

        // Read and write packets to shared memory
        pcpp::RawPacket raw_packet;
        while (reader->getNextPacket(raw_packet)) {
            pcpp::Packet parsed_packet(&raw_packet);
            /* std::cout << parsed_packet.toString() << std::endl; */

            // Capture the current time before writing the packet
            auto write_start = std::chrono::high_resolution_clock::now();

            // Write the packet to shared memory
            bool write_success = shm_writer.WritePacket(raw_packet);

            // Capture the current time after writing the packet
            auto write_end = std::chrono::high_resolution_clock::now();

            if (write_success) {
                packet_number++;

                // Calculate the duration of WritePacket execution in microseconds
                auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(write_end -
                                                                                        write_start)
                                           .count();

                // Log the result to the CSV file in the format: format, iteration, packet, time_us
                csv_file << "pcap," << iteration_number << "," << packet_number << ","
                         << duration_ns << "\n";

                /* std::cout << "Wrote packet to shared memory in " << duration_ns << " ns" */
                /*           << std::endl; */
            } else {
                std::cerr << "Failed to write packet to shared memory" << std::endl;
                // Optionally, log this event in the CSV as well with a special time value (e.g.,
                // -1)
                csv_file << "pcap," << iteration_number << "," << (packet_number + 1) << ",-1\n";
                // Assuming m_NumOfPacketsNotWritten_ is accessible here
                // m_NumOfPacketsNotWritten_++;
            }
        }

        // After processing, write the pcap files from shared memory
        shm_writer.DumpPcapFilesToDisk("capture_");

        // Close the CSV file
        csv_file.close();

        reader->close();
        shm_writer.close();  // Ensure all data is flushed and handlers are closed
    } catch (std::system_error const &e) {
        std::cerr << "System error: " << e.what() << std::endl;
        return 1;
    } catch (std::exception const &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
