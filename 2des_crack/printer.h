#ifndef PRINTER_H
#define PRINTER_H

#include <ostream>
#include <mutex>

std::ostream&
print_one(std::ostream& os)
{
    return os<<std::endl;
}

std::mutex&
get_cout_mutex()
{
    static std::mutex m;
    return m;
}

template <class A0, class ...Args>
std::ostream&
print_one(std::ostream& os, const A0& a0, const Args& ...args)
{
    os << a0;
    return print_one(os, args...);
}

template <class ...Args>
std::ostream&
print(std::ostream& os, const Args& ...args)
{
    return print_one(os, args...);
}

template <class ...Args>
std::ostream&
print(const Args& ...args)
{
    std::lock_guard<std::mutex> _(get_cout_mutex());
    return print(std::cout, args...);
}
#endif // !PRINTER_H
