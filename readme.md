This is a simple solution to get around kallsyms_lookup_name no longer being exported.

It uses kprobe to get the name of the function you are trying to hook. In this case it is a proof of concept to hook the system call table.
