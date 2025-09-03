import asyncio
import websockets
import json
import jwt
import os
from dotenv import load_dotenv
from urllib.parse import parse_qs, urlparse

print("using websockets:", websockets.__version__)

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key-for-dev")

# { room_id: { websocket: username } }
CONNECTED_ROOMS = {}


async def broadcast_user_count(room_id):
    if room_id in CONNECTED_ROOMS and CONNECTED_ROOMS[room_id]:
        user_count_message = json.dumps(
            {
                "type": "user_count_update",
                "room": room_id,
                "count": len(CONNECTED_ROOMS[room_id]),
            }
        )
        await asyncio.gather(
            *[
                client.send(user_count_message)
                for client in CONNECTED_ROOMS[room_id].keys()
            ]
        )


async def handler(websocket, path):
    try:
        # 1. URL에서 토큰과 room_id 파싱
        query_params = parse_qs(urlparse(path).query)
        token = query_params.get("token", [None])[0]
        room_id = query_params.get("room", ["default"])[0]
        
        username = '정글러'

        if not token:
            print(f"토큰 검증 실패: {e}")
            # await websocket.close(1011, "인증 토큰이 없습니다.")
            # return

        # # 2. 토큰 검증
        # payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        # print(f"payload", payload)
        # username = payload.get("username", "익명")

    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
        print(f"토큰 검증 실패: {e}")
        await websocket.close(1011, "유효하지 않은 토큰입니다.")
        return
    except Exception as e:
        print(f"인증 중 오류 발생: {e}")
        await websocket.close(1011, "인증 처리 중 오류 발생")
        return
    
    # --- 방에 등록 ---
    if room_id not in CONNECTED_ROOMS:
        CONNECTED_ROOMS[room_id] = {}
    CONNECTED_ROOMS[room_id][websocket] = username

    print(f"[{room_id}] '연결 성공. 현재 접속자: {len(CONNECTED_ROOMS[room_id])}명")

    # 입장 메시지 + 인원수 갱신
    entry_message = json.dumps(
        {"type": "system", "content": f"{username} 님이 입장했습니다."}
    )
    for client in CONNECTED_ROOMS[room_id].keys():
        await client.send(entry_message)
    await broadcast_user_count(room_id)

    try:
        async for message in websocket:
            print(f"[수신] {message!r}")
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                # JSON 파싱 실패 → 그냥 에코
                await websocket.send(json.dumps({
                    "type": "error",
                    "content": f"잘못된 메시지 형식: {message}"
                }))
                continue

            broadcast_data = {
                "type": "chat",
                "room": room_id,
                "user": username,
                "content": data.get("content"),
                "profileColor": data.get("profileColor"),
                "textColor": data.get("textColor"),
            }
            for client in CONNECTED_ROOMS[room_id].keys():
                await client.send(json.dumps(broadcast_data))

    finally:
        # --- 퇴장 처리 ---
        del CONNECTED_ROOMS[room_id][websocket]
        exit_message = json.dumps(
            {"type": "system", "content": f"{username} 님이 퇴장했습니다."}
        )
        for client in CONNECTED_ROOMS[room_id].keys():
            await client.send(exit_message)
        await broadcast_user_count(room_id)

        # 방이 비면 삭제
        if not CONNECTED_ROOMS[room_id]:
            del CONNECTED_ROOMS[room_id]

        print(
            f"[{room_id}] '{username}'님 연결 종료. 현재 접속자: {len(CONNECTED_ROOMS.get(room_id, {}))}명"
        )


async def main():
    async with websockets.serve(handler, "0.0.0.0", 5000):
        print("웹소켓 서버를 시작합니다 (ws://<서버IP>:5000)")
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
