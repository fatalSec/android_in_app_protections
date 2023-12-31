var do_dlopen = null;
var call_constructor = null;
Process.findModuleByName('linker64').enumerateSymbols().forEach(function(symbol){
    if(symbol.name.indexOf("do_dlopen") >= 0){
        do_dlopen = symbol.address;
    } else if (symbol.name.indexOf("call_constructor") >= 0){
        call_constructor = symbol.address;
    }
})

var lib_loaded = 0;
Interceptor.attach(do_dlopen, function(){
    var library_path = this.context.x0.readCString();
    if(library_path.indexOf("libinappprotections.so") >= 0){
        Interceptor.attach(call_constructor, function(){
            if(lib_loaded == 0){
                var native_mod = Process.findModuleByName("libinappprotections.so");
                console.log(`inappprotections library is loaded at ${native_mod.base}`);
                hookSVC(native_mod.base);
                hookImportedFunctions();
            }
            lib_loaded = 1;
        })
    }
})

Java.perform(function(){
    let MainActivity = Java.use("com.fatalsec.inappprotections.MainActivity");
    MainActivity["detectRoot"].implementation = function(){
        console.log("detectRoot() is called.");
        let ret = this.detectRoot();
        console.log(`detectRoot() return value is: ${ret}`);
        return ret;
    }
})



function hookImportedFunctions(){
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"),{
        onEnter: function(args){
            console.log(`fopen: ${args[0].readCString()}`);
        }
    })

    Interceptor.attach(Module.findExportByName("libc.so", "stat"),{
        onEnter: function(args){
            if(args[0].readCString().indexOf("/selinux") >= 0){
                Memory.protect(args[0], Process.pointerSize, 'rwx');
                args[0].writeUtf8String("/non/existing");
            }
            console.log(`stat: ${args[0].readCString()}`);
        }
    })

    Interceptor.attach(Module.findExportByName("libc.so", "access"),{
        onEnter: function(args){
            if(args[0].readCString().indexOf("/su") >= 0){
                args[0].writeUtf8String("/dont/exist");
            }
            console.log(`access: ${args[0].readCString()}`);
        }
    })

    Interceptor.attach(Module.findExportByName("libc.so", "strstr"),{
        onEnter: function(args){
            if(args[1].readCString().indexOf("zygote") >= 0){
                args[1].writeUtf8String("blabla");
            }
            if(args[1].readCString().indexOf("magisk") >= 0){
                args[1].writeUtf8String("blabla");
            }
            console.log(`strstr: haystack -> ${args[0].readCString()}, needle -> ${args[1].readCString()}`);
        }
    })

}

function hookSVC(base_addr){
    Interceptor.attach(base_addr.add(0x00001f8c), function(){
        var path = this.context.x1.readCString();
        this.context.x1.writeUtf8String("/non/existing");
        console.log(`SVC: ${path}`);
    })

    Interceptor.attach(base_addr.add(0x00001fa8), function(){
        var path = this.context.x1.readCString();
        this.context.x1.writeUtf8String("/non/existing");
        console.log(`SVC: ${path}`);
    })

    Interceptor.attach(base_addr.add(0x00001fc4), function(){
        var path = this.context.x1.readCString();
        this.context.x1.writeUtf8String("/non/existing");
        console.log(`SVC: ${path}`);
    })

    Interceptor.attach(base_addr.add(0x00001fe0), function(){
        var path = this.context.x1.readCString();
        this.context.x1.writeUtf8String("/non/existing");
        console.log(`SVC: ${path}`);
    })

    Interceptor.attach(base_addr.add(0x00001ffc), function(){
        var path = this.context.x1.readCString();
        this.context.x1.writeUtf8String("/non/existing");
        console.log(`SVC: ${path}`);
    })
}