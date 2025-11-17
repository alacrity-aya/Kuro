#pragma once

#include <iostream>
#include <memory>
#include <mutex>
template<typename T>
class Singleton {
protected:
    Singleton() = default;
    Singleton(const Singleton<T>&) = delete;
    Singleton& operator=(const Singleton<T>& st) = delete;
    static std::shared_ptr<T> instance;

public:
    [[nodiscard]] static std::shared_ptr<T> get_instance() {
        static std::once_flag s_flag;
        std::call_once(s_flag, [&]() { instance = std::shared_ptr<T>(new T); });
        return instance;
    }
    void print_address() {
        std::cout << instance.get() << std::endl;
    }
    ~Singleton() = default;
};
template<typename T>
std::shared_ptr<T> Singleton<T>::instance = nullptr;
