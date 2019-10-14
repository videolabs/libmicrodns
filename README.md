microdns
========

microdns is an **mDNS** library, focused on being **simple** and **cross-platform**.

Minimal mDNS resolver (and announcer) library
---------------------------------------------

This library **microdns** is still in development, and therefore can still have bugs.

The goal is to have a simple library to listen and create mDNS announces,
without the complexity of larger libraries like *avahi*.

This means that the API is quite *low-level* and that the code is in C.
Bindings to other languages are welcome.


License
-------

microdns is available under the LGPL license. People who want *(or need)* a commercial license can acquire one.


CoC
---

The [VideoLAN Code of Conduct](https://wiki.videolan.org/CoC) applies to this project.


Installation
------------
    meson builddir && ninja -C builddir

    # ninja -C builddir install
