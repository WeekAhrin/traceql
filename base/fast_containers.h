#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace traceql {

    /// @brief 64-bit FNV-1a hash for byte sequences.
    [[nodiscard]] inline uint64_t fnv1a64(std::string_view sv) noexcept {
        uint64_t hash = 14695981039346656037ULL;
        for (const unsigned char ch : sv) {
            hash ^= static_cast<uint64_t>(ch);
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    /// @brief Zero-copy string interning pool backed by std::deque<std::string> for pointer
    ///        stability and an open-addressing FNV-1a hash table for O(1) lookup.
    class StringPool {
      public:
        static constexpr uint32_t kInvalidId = UINT32_MAX;

        StringPool() = default;

        /// @brief Interns @p sv and returns its stable uint32_t ID.
        uint32_t intern(std::string_view sv) {
            if (buckets_.empty() || (strings_.size() + 1) * 10 >= buckets_.size() * 7) {
                rehash(buckets_.empty() ? 64 : buckets_.size() * 2);
            }
            const size_t mask = buckets_.size() - 1;
            size_t idx = static_cast<size_t>(fnv1a64(sv)) & mask;
            for (;;) {
                const uint32_t existing = buckets_[idx];
                if (existing == kInvalidId) {
                    const uint32_t id = static_cast<uint32_t>(strings_.size());
                    strings_.emplace_back(sv);
                    buckets_[idx] = id;
                    return id;
                }
                if (strings_[existing] == sv) {
                    return existing;
                }
                idx = (idx + 1) & mask;
            }
        }

        /// @brief Looks up @p sv without inserting. Returns kInvalidId if not found.
        [[nodiscard]] uint32_t find(std::string_view sv) const noexcept {
            if (buckets_.empty()) {
                return kInvalidId;
            }
            const size_t mask = buckets_.size() - 1;
            size_t idx = static_cast<size_t>(fnv1a64(sv)) & mask;
            for (;;) {
                const uint32_t existing = buckets_[idx];
                if (existing == kInvalidId) {
                    return kInvalidId;
                }
                if (strings_[existing] == sv) {
                    return existing;
                }
                idx = (idx + 1) & mask;
            }
        }

        /// @brief Returns a string_view for @p id, or empty view if out of range.
        [[nodiscard]] std::string_view view(uint32_t id) const noexcept {
            if (id >= strings_.size()) {
                return {};
            }
            return strings_[id];
        }

        [[nodiscard]] size_t size() const noexcept {
            return strings_.size();
        }
        [[nodiscard]] bool empty() const noexcept {
            return strings_.empty();
        }

        void clear() noexcept {
            strings_.clear();
            buckets_.clear();
        }

      private:
        void rehash(size_t new_cap) {
            buckets_.assign(new_cap, kInvalidId);
            const size_t mask = new_cap - 1;
            for (uint32_t id = 0; id < static_cast<uint32_t>(strings_.size()); ++id) {
                size_t idx = static_cast<size_t>(fnv1a64(strings_[id])) & mask;
                while (buckets_[idx] != kInvalidId) {
                    idx = (idx + 1) & mask;
                }
                buckets_[idx] = id;
            }
        }

        std::deque<std::string> strings_;
        std::vector<uint32_t> buckets_;
    };

    /// @brief Cache-friendly open-addressing linear-probing hash map.
    template <typename K, typename V, typename Hash = std::hash<K>, typename KeyEqual = std::equal_to<K>>
    class FlatHashMap {
      public:
        struct Slot {
            K key{};
            V value{};
            bool occupied = false;
        };

        FlatHashMap() = default;

        explicit FlatHashMap(size_t initial_capacity) {
            reserve(initial_capacity);
        }

        /// @brief Inserts or assigns @p value for @p key. Returns true if a new key was inserted.
        bool insert_or_assign(K key, V value) {
            if (slots_.empty() || (size_ + 1) * 10 >= slots_.size() * 7) {
                rehash(slots_.empty() ? 16 : slots_.size() * 2);
            }
            const size_t mask = slots_.size() - 1;
            size_t idx = hash_(key) & mask;
            for (;;) {
                Slot &slot = slots_[idx];
                if (!slot.occupied) {
                    slot.key = std::move(key);
                    slot.value = std::move(value);
                    slot.occupied = true;
                    ++size_;
                    return true;
                }
                if (eq_(slot.key, key)) {
                    slot.value = std::move(value);
                    return false;
                }
                idx = (idx + 1) & mask;
            }
        }

        /// @brief Returns pointer to value if @p key exists, otherwise nullptr.
        [[nodiscard]] V *find(const K &key) noexcept {
            if (slots_.empty()) {
                return nullptr;
            }
            const size_t mask = slots_.size() - 1;
            size_t idx = hash_(key) & mask;
            for (;;) {
                Slot &slot = slots_[idx];
                if (!slot.occupied) {
                    return nullptr;
                }
                if (eq_(slot.key, key)) {
                    return &slot.value;
                }
                idx = (idx + 1) & mask;
            }
        }

        /// @brief Returns const pointer to value if @p key exists, otherwise nullptr.
        [[nodiscard]] const V *find(const K &key) const noexcept {
            if (slots_.empty()) {
                return nullptr;
            }
            const size_t mask = slots_.size() - 1;
            size_t idx = hash_(key) & mask;
            for (;;) {
                const Slot &slot = slots_[idx];
                if (!slot.occupied) {
                    return nullptr;
                }
                if (eq_(slot.key, key)) {
                    return &slot.value;
                }
                idx = (idx + 1) & mask;
            }
        }

        [[nodiscard]] bool contains(const K &key) const noexcept {
            return find(key) != nullptr;
        }

        [[nodiscard]] size_t size() const noexcept {
            return size_;
        }
        [[nodiscard]] bool empty() const noexcept {
            return size_ == 0;
        }

        void clear() noexcept {
            for (Slot &slot : slots_) {
                if (slot.occupied) {
                    slot.occupied = false;
                    slot.key = K{};
                    slot.value = V{};
                }
            }
            size_ = 0;
        }

        void reserve(size_t count) {
            if (count == 0) {
                return;
            }
            const size_t needed = (count * 10) / 7 + 1;
            size_t cap = 16;
            while (cap < needed) {
                cap *= 2;
            }
            if (cap > slots_.size()) {
                rehash(cap);
            }
        }

      private:
        void rehash(size_t new_cap) {
            std::vector<Slot> old_slots = std::move(slots_);
            slots_.assign(new_cap, Slot{});
            const size_t mask = new_cap - 1;
            for (Slot &old : old_slots) {
                if (!old.occupied) {
                    continue;
                }
                size_t idx = hash_(old.key) & mask;
                while (slots_[idx].occupied) {
                    idx = (idx + 1) & mask;
                }
                slots_[idx].key = std::move(old.key);
                slots_[idx].value = std::move(old.value);
                slots_[idx].occupied = true;
            }
        }

        std::vector<Slot> slots_;
        size_t size_ = 0;
        [[no_unique_address]] Hash hash_{};
        [[no_unique_address]] KeyEqual eq_{};
    };

} // namespace traceql
