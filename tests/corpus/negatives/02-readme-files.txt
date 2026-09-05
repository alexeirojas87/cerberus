# MyProject

## Configuration

Set your API key in the environment:

```bash
export OPENAI_API_KEY="sk-your-key-here"
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
```

## Authentication

The API uses bearer tokens. Generate a token in the dashboard:

```
Authorization: Bearer YOUR_TOKEN_HERE
```

## Database

Update the connection string in `.env`:

```
DB_PASSWORD=your_password_here
```

## GitHub

Create a personal access token at https://github.com/settings/tokens and set:

```bash
export GITHUB_TOKEN=ghp_your_token_here
```

## Examples

For testing purposes only, do not use real data.
The sample email user@example.com is an allowed test address.
The test phone number 555-0199 is for documentation only.
The credit card number 4111 1111 1111 1111 is a well-known test number from Visa.
