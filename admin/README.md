Endpoints:
All the operations and results must be filtered by the Authentified user access.

- [GET] `/admin/elections` : Returns all elections

- [GET] `/admin/elections/[electionId]` : Returns the provided electionId information

- [POST] `/admin/elections` : Creates a new Census and attaches it to a new Election from the defined data. Returns the new Election ID.
Request JSON body example:
{ "handlers": 
    [
        {
            "handler": "oauth",
            "service": "facebook",
            "mode": "usernames",
            "data": ["12345","nigeon@gmail.com"]
        },
        {
            "handler": "oauth",
            "service": "github",
            "mode": "usernames",
            "data": ["nigeon"]
        },
        {
            "handler": "sms",
            "data": ["`666666666`", "637840295"]
        }
    ]
}

- [DELETE] `/admin/elections/[electionId] : Deletes election ID

- [GET] `/admin/elections/[electionId]/users : List users in election

- [POST] `/admin/elections/[electionId]/users : Add user in election
Request JSON body example:
{
    "handler": "oauth",
    "service": "facebook",
    "mode": "usernames",
    "data": "nigeon@gmail.com",
    "consumed": false
}

- [GET] `/admin/elections/[electionId]/users/[user] : Get user

- [PUT] `/admin/elections/[electionId]users/[user] : Edits user
Request JSON body example:
{
    "consumed": true
}

- [DELETE] `/admin/elections/[electionId]users/[user] : Deletes user

- [GET] `/admin/elections/[electionId]/users : List of users in the elections