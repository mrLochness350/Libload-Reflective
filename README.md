# Libload Reflective

This crate allows loading dynamic libraries into memory from bytes, rather than from disk.
A lot of this code was taken from the `libloading` crate, because I thought their implementation of `Symbol<T>` was already done and it didn't need a lot of modifications for it to work with in-memory libraries.
For Windows it uses Reflective DLL loading, and for Linux it uses anonymous file-descriptors to load the library into memory.
I am by no means expecting people to use this, since it's still messy, and I want to clean and reformat the code to be prettier.
Feel free to open issues or PRs to make it better.

I only tested this on Windows 11 and Ubuntu 22.04, so be advised.

## Why?

I wanted to implement a custom "plugin" system for the C2 framework (payload and server) that I'm working on, and I couldn't find something that fit my needs, so I decided to implement my own system for this.

## Example usage

```rust
type AddFn = fn(usize, usize) -> usize;

fn main() -> Result<(), ReflectError> {
    let data = vec![/*Library bytes*/]
    let lib = ReflectedLibrary::new(data)?;
    let add: Symbol<AddFn> = lib.get(b"add")?;
    let result = add(1,2);
    println!("Result: {res}");
}
```

## References

* <https://github.com/stephenfewer/ReflectiveDLLInjection/>
* <https://github.com/memN0ps/venom-rs>
* <https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection>
* <https://docs.rs/libloading/latest/libloading/>
* <https://man7.org/linux/man-pages/man2/memfd_create.2.html>
* <https://stackoverflow.com/questions/5053664/dlopen-from-memory>
