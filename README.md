# MulRecCodes

## Vulnerability Dataset

We do **not** publicly release our vulnerability dataset. Therefore, if you wish to use our tool, you will need to collect your own vulnerability dataset and place it in the appropriate directory. For example, in our project, the dataset is stored in the `/cache/old_new_funcs` folder. Inside this folder, subdirectories are named after programming languages. Within each subdirectory, vulnerable and patched functions are stored separately.

The structure of the vulnerability dataset is as follows:

```
/cache/old_new_funcs/
├── python3/
│ ├── old/ # vulnerable functions
│ └── new/ # patched functions
├── java/
│ ├── old/
│ └── new/
...
```

## Supported Programming Languages

Due to limitations in the datasets we have collected, the currently supported languages are listed in the `mygrammars.json` file. The corresponding ANTLR grammar files are located in the `mygrammars-v4` folder.

To extend support to other languages, simply provide a dataset for the new language. You can then add the corresponding grammar files and update `mygrammars.json` accordingly. For details on ANTLR grammars, refer to the [official ANTLR4 repository](https://github.com/antlr/grammars-v4).

---

## Target Projects for Detection

Projects to be analyzed must be described in JSON format, as shown in the `cppjson` file. The `"language"` field should be written using one of the following formats:

- `"Python3"`
- `"Java"`
- `"Ruby"`
- `"JavaScript"`
- `"Go"`
- `"Php"`
- `"CPP14"`
- `"CSharp"`

If you wish to support additional languages, ensure that the `"language"` value matches the `"name"` field you define in `mygrammars.json`.

---

## Configuration File

Before running the tool, you need to modify the configuration file `config.ini`. Key fields include:

- `input_json`: Path to the JSON file describing the target project.
- `vuln_data_dir`: Directory containing the vulnerability dataset.
- `projects_dir`: Directory where the target project is cloned or stored.
- Other fields define the output paths for results and logs, as well as several threshold parameters used in our method.

You can adjust these parameters for more flexible detection settings.

---

## Running the Tool

To run the tool, simply execute:

```bash
python main.py
