# VirtIO Paravirtualized cryptographic character device for QEMU-KVM

This exercise contains paradigm code for the implementation of a paravirtualized character device that exports the native `/dev/crypto` device of cryptodev to a QEMU VM. 

* Client-server chat over TCP/IP sockets (`/no_encryption`)
 
 For testing purpises, we first implement a simple chat system based on the `client-server` architecture, using TCP/IP UNIX sockets. 

* Encrypted chat over TCP/IP sockets (`/encryption`) 

 Next, we added encryption functionality to the aforementioned client-server system. The implementation preserves the sockets API usage providing transparency and transmiting only the encrypted text over the socket. The implementation uses the native cryptodev `/dev/crypto` character device. 

* Paravirtualized cryptographic driver device (`/paravirt_encryption`)

 Using the client-server system implemented in the context of two QEMU virtual machines we faced serious performaace overhead, mainly from the cryptodev device that is also emulated. For this reason, we implemented a paravirtualized character device for each of the two guests that exposes the native `/dev/crypto` of the host.

 The driver is composed of two parts, the frontend that is executed isnide the character device driver of the guest and the backend that is executed in host userspace. Those two parts communicate usnig VirtIO paradigm principles.  