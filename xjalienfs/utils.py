from xjalienfs import alien


async def get_completer_list(websocket):
    await alien.websocket.send(alien.CreateJsonCommand('ls'))
    ls_result = await alien.websocket.recv()
    ls_result = alien.json.loads(ls_result)
    ls_list = []
    for element in ls_result['results']:
        list.append(ls_list, element['message'])
    list.append(ls_list, '..')
    return ls_list
