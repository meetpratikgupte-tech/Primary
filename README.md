# Primary

## Microsoft Sentinel automated criticality labels

Use this KQL mapping in the Sentinel dashboard query output to display friendly
names for the automated criticality values:

```kql
| extend automatedCriticalityName = case(
    automatedCriticality == 5, "Crown Jewel",
    automatedCriticality == 4, "Business-Critical",
    tostring(automatedCriticality)
)
```

If the output is a string that already contains values such as
`automatedCriticality:5`, replace them before rendering:

```kql
| extend output = replace_string(output, "automatedCriticality:5", "Crown Jewel")
| extend output = replace_string(output, "automatedCriticality:4", "Business-Critical")
```
