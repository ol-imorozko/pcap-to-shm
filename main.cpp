#include <Packet.h>
#include <PcapFileDevice.h>
#include <RawPacket.h>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>

#include "shared_memory.h"
#include "shm_device.h"

/**
 * @brief Print the usage instructions for this program.
 *
 * This function prints out instructions on how to run the program, including command-line arguments
 * and what each option does.
 */
static void PrintHelp(std::string_view program_name) {
    std::cout
            << "Usage: " << program_name << " [options] <pcap_file> <iteration_number>\n\n"
            << "Options:\n"
            << "  -h, --help       Show this help message and exit.\n\n"
            << "Description:\n"
            << "This program reads packets from a given pcap file and writes them to a shared "
               "memory "
               "segment using a ring-like structure. The shared memory is then segmented into a "
               "fixed number of 'virtual pcap files', cycling through them as needed. When done, "
               "the program dumps all these segments to disk as separate pcap files, simulating a "
               "ring-buffer capture mechanism (similar to how tools like Wireshark handle "
               "multiple output files).\n\n"
            << "The 'iteration_number' is a user-specified integer that can be used to identify "
               "distinct runs of this process. The program also logs the time taken to write each "
               "packet into shared memory (in nanoseconds) to a CSV file, "
               "\"result.csv\".\n\n"
            << "Example:\n"
            << "  " << program_name << " input.pcap 42\n\n";
}

/**
 * @brief Parse the iteration number from a string.
 *
 * @param str The string representing the iteration number.
 * @return std::optional<int> Returns the iteration number if parsing was successful, or
 * std::nullopt otherwise.
 */
[[nodiscard]] static std::optional<int> ParseIterationNumber(std::string_view str) {
    try {
        int value = std::stoi(std::string(str));
        return value;
    } catch (std::invalid_argument const &) {
        return std::nullopt;
    } catch (std::out_of_range const &) {
        return std::nullopt;
    }
}

/**
 * @brief Ensure the CSV file is ready for logging and write the header if it's empty.
 *
 * @param csv_file_path Path to the CSV file.
 * @return std::ofstream The open file stream ready for append, or a closed stream if failed.
 */
[[nodiscard]] static std::ofstream PrepareCsvFile(std::string const &csv_file_path) {
    bool write_header = false;
    if (!std::filesystem::exists(csv_file_path)) {
        write_header = true;
    } else {
        if (std::filesystem::file_size(csv_file_path) == 0) {
            write_header = true;
        }
    }

    std::ofstream csv_file(csv_file_path, std::ios::out | std::ios::app);
    if (!csv_file.is_open()) {
        std::cerr << "Failed to open " << csv_file_path << " for writing" << std::endl;
        return {};
    }

    if (write_header) {
        csv_file << "format,iteration,packet,time_ns\n";
    }

    return csv_file;
}

/**
 * This program:
 * - Reads packets from the specified pcap file.
 * - Writes them into shared memory configured as a ring-buffer of multiple pcap segments.
 * - Logs the time taken to write each packet to a CSV file.
 * - After processing all packets, dumps the captured segments from shared memory to disk as
 * separate pcap files.
 *
 * Command-line arguments:
 * - <pcap_file>: Path to the input pcap file.
 * - <iteration_number>: Integer identifying the run/iteration.
 * - Optional: -h or --help to display usage information.
 */
int main(int argc, char *argv[]) {
    // Handle help option
    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            PrintHelp(argv[0]);
            return 0;
        }
    }

    if (argc != 3) {
        std::cerr << "Invalid arguments. Use -h or --help for usage instructions.\n";
        return 1;
    }

    std::string_view pcap_file_name = argv[1];
    auto iteration_number_opt = ParseIterationNumber(argv[2]);
    if (!iteration_number_opt.has_value()) {
        std::cerr << "Invalid iteration number: " << argv[2] << std::endl;
        return 1;
    }
    int iteration_number = iteration_number_opt.value();

    constexpr std::string_view shm_name = "/my_shared_memory";
    constexpr size_t shm_size = 30 * 1024;  // 30 Kb of shared memory
    constexpr size_t pcap_files = 3;        // number of pcap segments in the ring

    std::string const csv_file_path = "result.csv";
    auto csv_file = PrepareCsvFile(csv_file_path);
    if (!csv_file.is_open()) {
        return 1;  // Error message already printed
    }

    try {
        SharedMemory shm(shm_name, shm_size);

        // Use PcapPlusPlus to open pcap file for reading
        auto reader = std::unique_ptr<pcpp::IFileReaderDevice>(
                pcpp::IFileReaderDevice::getReader(std::string(pcap_file_name)));

        if (!reader || !reader->open()) {
            std::cerr << "Error opening the pcap file: " << pcap_file_name << std::endl;
            return 1;
        }

        // Initialize the shared memory writer with a ring of pcap segments
        // This creates `pcap_files` segments in the shared memory, each can hold multiple packets.
        // Once a segment runs out of space, it moves to the next one in a circular manner.
        pcpp::PcapShmWriterDevice shm_writer(shm.Get(), shm.Size(), pcap_files);

        if (!shm_writer.open()) {
            std::cerr << "Cannot open shared memory for writing" << std::endl;
            return 1;
        }

        size_t packet_number = 0;
        pcpp::RawPacket raw_packet;

        // Read packets from the input pcap and write them to the shared memory device
        while (reader->getNextPacket(raw_packet)) {
            auto write_start = std::chrono::high_resolution_clock::now();
            bool write_success = shm_writer.WritePacket(raw_packet);
            auto write_end = std::chrono::high_resolution_clock::now();

            if (write_success) {
                ++packet_number;
                auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(write_end -
                                                                                        write_start)
                                           .count();
                csv_file << "pcap," << iteration_number << "," << packet_number << ","
                         << duration_ns << "\n";
            } else {
                // Failed to write packet
                std::cerr << "Failed to write packet " << (packet_number + 1) << " to shared memory"
                          << std::endl;
                csv_file << "pcap," << iteration_number << "," << (packet_number + 1) << ",-1\n";
            }
        }

        // After writing all packets, dump the segments as pcap files to disk.
        // The naming scheme is "capture_1.pcap", "capture_2.pcap", etc.
        shm_writer.DumpPcapFilesToDisk("capture_");

        // Close reader and CSV file streams
        reader->close();
        shm_writer.close();
        csv_file.close();

    } catch (std::system_error const &e) {
        std::cerr << "System error: " << e.what() << std::endl;
        return 1;
    } catch (std::exception const &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
