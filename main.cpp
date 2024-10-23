#include <iostream>
#include <string>
#include <string_view>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cerrno>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <PcapFileDevice.h>
#include <RawPacket.h>
#include <Packet.h>

// Hexdump function as provided
inline std::string hexdump(std::string_view data)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0'); // Set hexadecimal formatting and fill character

    const size_t size = data.size();

    for (size_t offset = 0; offset < size; offset += 16)
    {
        // Output the offset
        oss << std::setw(8) << offset << "  ";

        // Prepare ASCII representation
        std::string ascii_representation;
        ascii_representation.reserve(16);

        const size_t line_size = std::min(size - offset, size_t(16));

        for (size_t i = 0; i < 16; ++i)
        {
            // Add extra space after 8 bytes
            if (i == 8)
            {
                oss << "  ";
            }
            else if (i != 0)
            {
                oss << ' ';
            }

            if (i < line_size)
            {
                const auto byte = static_cast<unsigned char>(data[offset + i]);
                oss << std::setw(2) << static_cast<int>(byte);

                ascii_representation += std::isprint(byte) ? byte : '.';
            }
            else
            {
                // Fill in spaces for alignment if line is shorter than 16 bytes
                oss << "  ";
                ascii_representation += ' ';
            }
        }

        // Append ASCII representation
        oss << "  |" << ascii_representation << "|\n";
    }

    return oss.str();
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }
    std::string pcapFileName = argv[1];

    // Open shared memory
    const char* shm_name = "/my_shared_memory";
    const size_t shm_size = 10 * 1024 * 1024; // 10 MB

    int shm_fd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1)
    {
        std::cerr << "Failed to open shared memory: " << strerror(errno) << std::endl;
        return 1;
    }

    if (ftruncate(shm_fd, shm_size) == -1)
    {
        std::cerr << "Failed to set size of shared memory: " << strerror(errno) << std::endl;
        return 1;
    }

    void* shm_ptr = mmap(0, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED)
    {
        std::cerr << "Failed to map shared memory: " << strerror(errno) << std::endl;
        return 1;
    }

    // Write "hello world" to shared memory
    const char* message = "hello world";
    size_t message_len = strlen(message);

    memcpy(shm_ptr, message, message_len);

    // Hexdump the written content
    std::string_view data_view(reinterpret_cast<char*>(shm_ptr), message_len);
    std::string dump = hexdump(data_view);

    std::cout << "Hexdump of shared memory content:" << std::endl;
    std::cout << dump << std::endl;

    // Open the pcap file
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(pcapFileName);
    if (!reader->open())
    {
        std::cerr << "Error opening the pcap file" << std::endl;
        return 1;
    }

    // Read and print packets
    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket))
    {
        pcpp::Packet parsedPacket(&rawPacket);
        std::cout << parsedPacket.toString() << std::endl;
    }

    // Cleanup
    reader->close();
    delete reader;

    if (munmap(shm_ptr, shm_size) == -1)
    {
        std::cerr << "Failed to unmap shared memory: " << strerror(errno) << std::endl;
    }

    if (close(shm_fd) == -1)
    {
        std::cerr << "Failed to close shared memory file descriptor: " << strerror(errno) << std::endl;
    }

    if (shm_unlink(shm_name) == -1)
    {
        std::cerr << "Failed to unlink shared memory: " << strerror(errno) << std::endl;
    }

    return 0;
}

