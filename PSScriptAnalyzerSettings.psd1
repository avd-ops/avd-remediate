# PSScriptAnalyzer settings for avd-remediate (used by CI and locally).
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
    )
}
