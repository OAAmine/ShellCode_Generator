Shellcode Generator (`shellcode_gen.py`) is a Python tool that enables users to generate polymorphic shellcodes for x86_64 architecture. This tool takes user-written assembly instructions as input and produces different shellcodes each time it's executed, enhancing evasion against signature-based detection mechanisms.

DISCLAIMER : THIS IS A WORK IN PROGRESS 

## Features

- Generate polymorphic shellcodes for x86_64 architecture.
- Write custom assembly instructions to create unique shellcodes.
- Enhance evasion by generating different shellcodes on each run.
- Easily integrate generated shellcodes into your security research or exploitation projects.

## Getting Started

1. **Clone the repository:**

   ```bash
   git clone https://github.com/OAAmine/ShellCode_Generator.git
   ```

2. **Write assembly instructions:**

   In the `shellcode_gen.py` file, write your custom assembly instructions using x86_64 architecture syntax. These instructions will be the basis for generating the polymorphic shellcode.

3. **Generate a polymorphic shellcode:**

   Run the generator script to assemble your instructions and produce a polymorphic shellcode:

   ```bash
   python shellcode_gen.py
   ```

   The generated shellcode will vary on each run, making it more difficult to detect.

4. **Integrate into your project:**

   Once you've generated a shellcode, you can integrate it into your exploit code or security research project.

## Writing Assembly Instructions

Edit the `assembly_instructions.asm` file with your custom assembly instructions. Ensure that your instructions follow the x86_64 architecture syntax.

## Example

The script generates shellcode for a reverse shell.

## Legal Disclaimer

This tool is intended for educational and research purposes only. Use it responsibly and only on systems you have the legal right to access. The authors are not responsible for any misuse or damage caused by this tool.

## Contributing

Contributions are welcome! If you have any ideas, suggestions, or improvements, feel free to open an issue or submit a pull request.

## License

This project is licensed under the  GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007 - see the [LICENSE](LICENSE) file for details.

---

*Note: This project is inspired by the concept of generating polymorphic shellcodes from user-provided assembly instructions. Always adhere to ethical guidelines and use this knowledge responsibly.*
```
