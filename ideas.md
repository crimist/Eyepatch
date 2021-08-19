## A

Current driver just hides self after unsigned load and then can read / write memory from kernel using socket/pipe

## B

Inspired by https://github.com/not-wlan/driver-hijack

* On init (set name length to 0 to avoid MmUnloadedDrivers)
* Walk drivers and match one with IOCTL
* Either
  * Find empty memory in that drivers space and write the function into it
  * Allocate some executable memory and write the function into that
* Highjack an IOCTL routine
  * Make sure to call original at the end though
* Unload driver
* 0 detection vectors?
