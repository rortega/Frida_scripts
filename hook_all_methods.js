Java.perform(function () {
    try {
        // Replace with your target class
        var className = "com.firstapp.utils.TextProcessor";
        var clazz = Java.use(className);

        // Verify class is loaded
        if (!clazz || !clazz.class) {
            console.log("Error: Class " + className + " not found or not loaded.");
            return;
        }

        // Get declared methods using reflection
        var methods = clazz.class.getDeclaredMethods();
        console.log("Hooking methods of " + className + ":");

        if (methods.length === 0) {
            console.log("  No methods found.");
        } else {
            methods.forEach(function (method) {
                var methodName = method.getName();
                console.log("  Hooking " + methodName);

                // Hook the method
                try {
                    clazz[methodName].implementation = function () {



                           var logMsg = "Method " + className + "." + methodName + "(";
                            for (var i = 0; i < arguments.length; i++) {
                                logMsg += "arg" + i + "=" + (arguments[i] == null ? "null" : arguments[i].toString());
                                if (i < arguments.length - 1) logMsg += ", ";
                            }
                            logMsg += ") called";
                            console.log(logMsg);


                             var result = this[methodName].apply(this, arguments);

                            // Log return value
                            var returnLog = "Method " + className + "." + methodName + " returned: " + 
                                            (result == null ? "null" : result.toString());
                            console.log(returnLog);
                        


        
                        // Call the original method and return its result
                        //return this[methodName].apply(this, arguments);
                        return result;
                    };
                } catch (e) {
                    console.log("  Failed to hook " + methodName + ": " + e.message);
                }
            });
        }
    } catch (e) {
        console.log("Error: " + e.message);
    }
    console.log("Hooking complete.");
});
