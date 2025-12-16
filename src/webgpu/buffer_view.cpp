#include <ligetron/webgpu/buffer_view.hpp>

// Use unnamed namespace for internal linkage
namespace {
std::shared_ptr<WGPUBuffer> make_storage(WGPUBuffer s) {
    return std::shared_ptr<WGPUBuffer>(new WGPUBuffer(s), [](WGPUBuffer *buf) {
        if (buf) {
            if (*buf)
                wgpuBufferDestroy(*buf);
            delete buf;            
        }
    });
}
}

namespace ligero::webgpu {

buffer_view::buffer_view() : storage_(nullptr) { }

buffer_view::buffer_view(WGPUBuffer buf)
    : buffer_view(buf, 0) { }

buffer_view::buffer_view(WGPUBuffer buf, size_t offset_bytes)
    : storage_(make_storage(buf)), offset_bytes_(offset_bytes)
{
    size_t ssize = storage_size();
    assert(offset_bytes <= ssize);
    size_bytes_ = offset_bytes <= ssize ?
                  ssize - offset_bytes : 0;
}

buffer_view::buffer_view(WGPUBuffer buf,
                         size_t offset_bytes,
                         size_t size_bytes)
    : storage_(make_storage(buf)),
      offset_bytes_(offset_bytes),
      size_bytes_(size_bytes)
{
    assert(offset_bytes + size_bytes <= storage_size());
}

buffer_view::buffer_view(buffer_view::storage_type s)
    : buffer_view(std::move(s), 0) { }

buffer_view::buffer_view(buffer_view::storage_type s,
                         size_t offset_bytes)
    : storage_(std::move(s)), offset_bytes_(offset_bytes)
{
    size_t ssize = storage_size();
    assert(offset_bytes <= ssize);
    size_bytes_ = offset_bytes <= ssize ?
                  ssize - offset_bytes : 0;
}

buffer_view::buffer_view(buffer_view::storage_type s,
                         size_t offset_bytes,
                         size_t size_bytes)
    : storage_(std::move(s)),
      offset_bytes_(offset_bytes),
      size_bytes_(size_bytes)
{
    assert(offset_bytes + size_bytes <= storage_size());
}

bool buffer_view::operator==(buffer_view other) const noexcept {
    return (storage_ == other.storage_) &&
           (offset_bytes_ == other.offset_bytes_) &&
           (size_bytes_ == other.size_bytes_);
}

size_t buffer_view::size() const noexcept {
    return size_bytes_;
}

size_t buffer_view::offset() const noexcept {
    return offset_bytes_;
}

size_t buffer_view::storage_size() const noexcept {
    return wgpuBufferGetSize(*storage_);
}

buffer_view::buffer_type buffer_view::get() const noexcept {
    return *storage_;
}

buffer_view::storage_type buffer_view::storage() const noexcept {
    return storage_;
}

buffer_view buffer_view::slice_bytes(size_t n_bytes, size_t from) const {
    assert(from + n_bytes <= size_bytes_);

    return buffer_view(storage_, n_bytes, offset_bytes_ + from);
}

// void buffer_view::destroy_source() const { }

}  // namespace ligero::webgpu
