
# Nice to know (Lizmat's blog)

Robert Alen Zimmerman: Bob Dylan
Farrokh Bulsara: Freddy Mercury
Stefani Germanotta: Lady Gaga

## rename files
rename -o .pm6 .rakumod *.pm6
rename -o .t .rakutest *.t

# Command line
Recognized options by GTK
See https://www.systutorials.com/docs/linux/man/7-gtk-options/

# Circular dependencies
* Solved by using `require`. This will compile imported modules at a later moment.
* It also does not have to be two-sided, i.e. not in both referring modules.
* As a side effect, I think this late binding is useful when a routine is not needed much and therefore not always need to import a module. Used in Gdk Visual which is referenced by Screen to get visuals. In this case, a `try` is not needed because the module exists.
  ```
  method get-screen ( --> Any ) {
    require ::('Gnome::Gdk3::Screen');
    ::('Gnome::Gdk3::Screen').new(
      :native-object(gdk_visual_get_screen(self._get-native-object-no-reffing))
    )
  }
  ```
# Catching exeptions
in callbacks the errors sometime fail to throw properly so insert next code to
trap it.
```
CATCH { default { .message.note; .backtrace.concise.note } }
```

```
CONTROL { when CX::Warn {  note .gist; .resume; } }
```
