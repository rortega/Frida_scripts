 Interceptor.attach(Module.findExportByName("/system/lib/libc.so", "open"), {
             onEnter: function(args) {
                var filename = Memory.readCString(ptr(args[0]));
                var x = Memory.readCString(ptr(args[1]));
                console.log('filename =', filename);
                console.log('filename =', x);
              },
              onLeave: function(retval) {
              }
});
