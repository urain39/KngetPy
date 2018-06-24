import os as _os
import sys as _sys

_DIGITS = "0123456789"
_DEFAULT_SECTION = '0x22CAFE!'

class IniException(Exception):
    pass

class IniFile():
    def __init__(self, filename=None):
        self._filename = filename
        self._section = _DEFAULT_SECTION

        self._props = {
            self._section: {}
        }

        if self._filename is not None:
            self._parser()

    def _parser(self):
        if not _os.path.exists(self._filename):
            raise IniException('Not found file named as [%s]' % self._filename)

        with open(self._filename, 'r') as _file:
            for _line in _file.readlines():
                _line = _line.strip()                   # No blank
                _line = _line.strip('\n')               # No newline

                if _line  == '' or _line[0] in (';', '#'):
                    continue                            # Skip comment or blank
                elif _line[0] == '[':
                    if _line[-1] != ']':
                        raise IniException('No closed section!')

                    self._section = _line[1:-1]         # Update section

                    if self._section == '':
                        raise IniException('Section is empty!')

                    if self._props.get(self._section) is None:
                        self._props.setdefault(self._section, {})
                    continue
                else:
                    if not '=' in _line[1:]:
                        raise IniException('SyntaxError at [%s]' % _line)

                    for i in range(len(_line)):
                        if _line[i] == '=':
                            key = _line[:i].strip()
                            value = _line[i+1:].strip()

                            # XXX: I know it's not a good way,
                            #    : But it's better to read isn't is?
                            
                            # XXX: if all([]) then we will get True.
                            if all([i in _DIGITS for i in value] or [None]):
                                self._props[self._section][key] = int(value)
                            else:
                                self._props[self._section][key] = str(value)
                            break

    def get(self, key, section=None):
        section = section or self._section

        if self._props.get(section) is None:
            raise IniException('Section is empty!')

        return self._props[section].get(key)

    def add(self, key, value, section=None):
        section = section or self._section

        if self._props.get(section) is None:
            self._props.setdefault(section, {})

        self._props[section][key] = value

    def delete(self, key, section=None):
        section = section or self._section

        if self._props.get(section) is None:
            return

        if self._props[section].get(key) is not None:
            del self._props[section][key]

        if len(self._props[section]) == 0:
            del self._props[section]

    def dump(self, fp=_sys.stdout):
        for section in self._props.keys():
            if section != _DEFAULT_SECTION:
                fp.write("[%s]\n" % section)

            for key in self._props[section].keys():
                fp.write("%s=%s\n" % (key, self._props[section][key]))

    def get_section(self, section=None):
        section = section or self._section

        if self._props.get(section) is None:
            raise IniException('Section is empty!')

        return self._props[section]

    def reset(self, props=None):
        self._props = props

    def section(self, section=None):
        section = section or self._section

        self._section = section
