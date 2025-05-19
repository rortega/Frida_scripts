Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.startsWith("com.firstapplicationi")) {
                console.log(className);
            }
        },
        onComplete: function () {
            console.log("Enumeration complete.");
        }
    });
});
