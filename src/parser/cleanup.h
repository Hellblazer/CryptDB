#pragma once

template<class T>
class cleanup_caller {
 public:
    cleanup_caller(T a) : action(a) {}
    ~cleanup_caller() { action(); }

 private:
    T action;
};

template<class T>
cleanup_caller<T>
cleanup(T a)
{
    return cleanup_caller<T>(a);
}
