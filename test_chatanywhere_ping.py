from openai import OpenAI

client = OpenAI(
    api_key="sk-PzGtSKui4MvwQa1lByn6HclLvK4FRoWw652YxnCx88cGxPM5",
    base_url="https://api.chatanywhere.tech/v1",
)

try:
    resp = client.chat.completions.create(
        model="gpt-4",  # 或 chatanywhere 控制台推荐的模型名
        messages=[{"role": "user", "content": "ping"}],
        timeout=15,
    )
    print("OK:", resp.choices[0].message.content[:50])
except Exception as e:
    print("Error:", type(e), e)