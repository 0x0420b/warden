#pragma once

#include <vector>
#include <cstring> // for memcpy
#include <cstdint>
#include <algorithm>

struct ByteBuffer {
private:
	std::vector<uint8_t> _data;
	size_t _pos;

public:
	ByteBuffer(std::vector<uint8_t> const & data) : _data(data), _pos(0u) {

	}

	ByteBuffer(size_t size) : _data(size), _pos(0u) { }

	void load(void* data, size_t size) {
		memcpy(_data.data(), data, std::min(size, _data.size()));
	}

	template <typename T>
	T read() {
		T out = *reinterpret_cast<const T*>(&_data[_pos]);
		_pos += sizeof(T);
		return out;
	}

	template <typename T>
	ByteBuffer& operator >> (T& out) {
		out = read<T>();
		return *this;
	}

	template <typename T>
	ByteBuffer& operator >> (std::vector<T>& out) {
		memcpy(out.data(), &_data[_pos], out.size() * sizeof(T));
		_pos += out.size() * sizeof(T);
		return *this;
	}

	size_t pos() const { return _pos; }

	void skip(size_t c) { _pos += c; }

	bool done() const {
		return _pos == _data.size();
	}

	template <typename T>
	T* insitu() {
		_pos += sizeof(T);
		return const_cast<T*>(reinterpret_cast<const T*>(&_data[_pos - sizeof(T)]));
	}

	const uint8_t* data() const { return _data.data(); }
	size_t size() { return _data.size(); }
};
