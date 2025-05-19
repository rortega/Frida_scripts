console.log("Starting function tracing...");

// Specify the target module (e.g., a native library)
const targetModule = "libnative.so"; // Replace with your module name

// Enumerate all exported functions in the module
Module.enumerateExports(targetModule, {
    onMatch: function (export) {
        // Only hook functions (skip variables or other exports)
        if (export.type === "function") {
            console.log(`Hooking function: ${export.name} at ${export.address}`);
            try {
                Interceptor.attach(ptr(export.address), {
                    onEnter: function (args) {
                        console.log(`Called: ${export.name}(${args[0]}, ${args[1]}, ...)`);
                    },
                    onLeave: function (retval) {
                        console.log(`Returned: ${export.name} -> ${retval}`);
                    }
                });
            } catch (e) {
                console.log(`Failed to hook ${export.name}: ${e}`);
            }
        }
    },
    onComplete: function () {
        console.log("Finished hooking exports.");
    }
});
