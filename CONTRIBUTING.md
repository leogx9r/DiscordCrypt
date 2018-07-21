## Any Merge Request Or Issue Reported Not Following These Guidelines Will Be Ignored

## Submitting Issues

Copy & Paste the following template when submitting an issue.

Keep the titles short and to the point.

```
`Title`: `< Issue Title >`

`Category`: `< Bug | Feature | Misc >`

`Description`:

    < Any information regarding the issue here. >
    < Be as detailed as possible. >
    
```

## Merge-Request Guidelines

Merge requests **not following** these guidelines will be **ignored**.

* Avoid overly-complex code. 
    Follow the [KISS](https://en.wikipedia.org/wiki/KISS_principle) guidelines.
* Ensure your code meets the project's current code-style.
* Test your changes personally before requesting them to be committed.
* Don't commit changes that simply refactor existing code or its code style.
* Use NodeJS modules supported by BetterDiscord in preference to writing your own methods.
* Avoid using code that can potential break on Discord updating. 
    If you *MUST*, write additional code that provides the same functionality in the event that 
        a break does occur.
* Comment each component of your changes using block quotes and be as detailed as 
    possible. ( `/* ... */` )
* Comment each function to in an ESDoc compatible format.
* Methods specific to Discord should begin with one underscores ( `_` ) and 
    be declared as static. ( If applicable. )
* Methods not strictly related to Discord, ( can be used outside in a testing environment ) 
    should begin with two underscores. ( `__` ) and should be declared as static. 
        ( If applicable. )
* Write tests for your changes to ensure they function correctly. These must be added to 
    [perform_tests.js](tests/perform-tests.js). 
    Be sure to follow the above guidelines when adding them.
* If your tests require generation of test vectors, write them in 
    [test-generator.js](tests/test-generator.js). 
    These test vectors SHOULD be added as JSON files within the `tests` folder.
