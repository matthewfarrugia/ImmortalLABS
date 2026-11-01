// labs_host.m
// -----------------------------------------------------------------------------
// A minimal, headless Audio Unit host whose only job is to load the Spitfire
// LABS plugin *in-process* and initialize it, so that a debugger attached to
// THIS process can observe the plugin building its Blowfish decryption key.
//
// Build (see build_host.sh):
//   clang -arch x86_64 -g -O0 labs_host.m -o labs_host \
//     -framework Foundation -framework CoreFoundation -framework AudioToolbox
//
// Need to build x86_64 as this is the slice where the 0xf37640 offset for the
// Blowfish constructor is valid.
// -----------------------------------------------------------------------------

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#include <dlfcn.h>
#include <stdio.h>

// Two no-op "marker" functions. They exist only so the debugger can set
// breakpoints by name at precise points in our flow. `noinline` + the inline
// asm keep the compiler from optimizing them away.
__attribute__((noinline)) void capture_ready(void) { __asm__ __volatile__(""); }
__attribute__((noinline)) void capture_done(void)  { __asm__ __volatile__(""); }

int main(int argc, const char **argv) {
    @autoreleasepool {
        // The installed LABS executable. We dlopen it first so the Mach-O image
        // is mapped into our address space *now*; that lets the debugger arm a
        // breakpoint inside the plugin before any decryption happens. The AU
        // system will reuse this same image (dyld dedupes by path).
        const char *pluginBin =
            "/Library/Audio/Plug-Ins/Components/LABS.component/Contents/MacOS/LABS";
        void *h = dlopen(pluginBin, RTLD_NOW | RTLD_GLOBAL);
        printf("[host] dlopen(%s) = %p\n", pluginBin, h);
        fflush(stdout);

        // >>> Debugger arms the Blowfish-constructor breakpoint at this point. <<<
        capture_ready();

        // Locate the LABS v2 AudioUnit in the component registry. The four-char
        // codes come straight from the plugin's Info.plist:
        //   type 'aumu' (kAudioUnitType_MusicDevice), subtype 'SfLb', mfr 'SpFi'.
        AudioComponentDescription desc = {0};
        desc.componentType         = kAudioUnitType_MusicDevice;
        desc.componentSubType      = 'SfLb';
        desc.componentManufacturer = 'SpFi';

        AudioComponent comp = AudioComponentFindNext(NULL, &desc);
        printf("[host] AudioComponentFindNext = %p\n", comp);
        if (!comp) { printf("[host] LABS AU not found in registry\n"); return 1; }

        // Instantiate (loads/opens the plugin in-process).
        AudioComponentInstance au = NULL;
        OSStatus st = AudioComponentInstanceNew(comp, &au);
        printf("[host] AudioComponentInstanceNew = %d au=%p\n", (int)st, au);
        if (st != noErr) return 2;

        // Initialize: license validation (decrypts lmdc) + content prep. This is
        // the step that builds the per-machine Blowfish key.
        st = AudioUnitInitialize(au);
        printf("[host] AudioUnitInitialize = %d\n", (int)st);

        // Also ask for the factory preset list, another path that can touch the
        // encrypted content index.
        CFArrayRef presets = NULL; UInt32 sz = sizeof(presets);
        OSStatus pst = AudioUnitGetProperty(au, kAudioUnitProperty_FactoryPresets,
                                            kAudioUnitScope_Global, 0, &presets, &sz);
        printf("[host] FactoryPresets query = %d presets=%p\n", (int)pst, presets);

        // Give any async init / content-scan work a moment to run and decrypt.
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 2.0, false);

        // >>> Debugger can stop here; by now the key has been built at least once.
        capture_done();

        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.5, false);
        printf("[host] done\n");
        return 0;
    }
}
