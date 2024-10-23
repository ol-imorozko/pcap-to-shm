#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string_view>
#include <sys/mman.h>
#include <system_error>
#include <unistd.h>

class SharedMemory {
public:
    SharedMemory(std::string_view name, size_t size)
        : name_(name), size_(size), shm_fd_(-1), shm_ptr_(nullptr) {
        shm_fd_ = shm_open(name_.data(), O_CREAT | O_RDWR, 0666);
        if (shm_fd_ == -1) {
            throw std::system_error(errno, std::generic_category(), "Failed to open shared memory");
        }

        if (ftruncate(shm_fd_, size_) == -1) {
            close(shm_fd_);
            throw std::system_error(errno, std::generic_category(),
                                    "Failed to set size of shared memory");
        }

        shm_ptr_ = mmap(nullptr, size_, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd_, 0);
        if (shm_ptr_ == MAP_FAILED) {
            close(shm_fd_);
            throw std::system_error(errno, std::generic_category(), "Failed to map shared memory");
        }
    }

    SharedMemory(SharedMemory const &) = delete;
    SharedMemory &operator=(SharedMemory const &) = delete;

    SharedMemory(SharedMemory &&other) noexcept
        : name_(other.name_), size_(other.size_), shm_fd_(other.shm_fd_), shm_ptr_(other.shm_ptr_) {
        other.shm_fd_ = -1;
        other.shm_ptr_ = nullptr;
    }

    SharedMemory &operator=(SharedMemory &&other) noexcept {
        if (this != &other) {
            Cleanup();
            name_ = other.name_;
            size_ = other.size_;
            shm_fd_ = other.shm_fd_;
            shm_ptr_ = other.shm_ptr_;
            other.shm_fd_ = -1;
            other.shm_ptr_ = nullptr;
        }
        return *this;
    }

    ~SharedMemory() {
        Cleanup();
    }

    void *Get() const {
        return shm_ptr_;
    }

    size_t Size() const {
        return size_;
    }

private:
    std::string_view name_;
    size_t size_;
    int shm_fd_;
    void *shm_ptr_;

    void Cleanup() {
        if (shm_ptr_ != nullptr) {
            munmap(shm_ptr_, size_);
        }
        if (shm_fd_ != -1) {
            close(shm_fd_);
        }
        shm_unlink(name_.data());
    }
};
