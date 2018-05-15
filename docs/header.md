# Ebookcoin API

Ebookcoin Wallet REST API. All api using **/api** prefix.

**How to work with API**

+ Information need to return.
+ Success parameter. Determines the success of a response.
+ Error perameter. Provided if the success parameter equal **"false"**.

API available only after wallet loading, before all routes will return:

    {
        "success" : false,
        "error" : "loading"
    }
