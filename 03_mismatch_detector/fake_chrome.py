import requests


headers = {
    "User-Agent": (
        "Mozilla/5.0 "
        "(Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/140.0.0.0 "
        "Safari/537.36"
    )
}


response = requests.get(
    "https://localhost:8444",
    headers=headers,
    verify=False,
)


print(
    response.status_code
)

print(
    response.text
)