# -*- coding: utf-8 -*-


def convert_to_int(data):
    return int.from_bytes(data, byteorder='big')


def _parse(data, count):
    p = 0
    result = list()
    for _ in range(count):
        length = convert_to_int(data[p:p + 2])
        p += 2
        value = data[p:p + length]
        p += length
        result.append(
            dict(
                value=value,
                length=length
            )
        )

    return [info['value'] for info in result], 7 + sum([info['length'] for info in result])


def parse_header(data):
    language_tag_length = convert_to_int(data[12:14])
    header_length = 14 + language_tag_length
    return dict(
        version=data[0],
        function_id=data[1],
        length=convert_to_int(data[2:5]),
        xid=convert_to_int(data[10:12]),
        language_tag_length=language_tag_length,
        language_tag=data[14:header_length].decode()
    ), header_length


def parse_url_entry(data):
    url_length = convert_to_int(data[3:5])
    auth_length = data[5 + url_length]
    length = 6 + url_length + auth_length
    return dict(
        lifetime=convert_to_int(data[1:3]),
        url=data[5:5 + url_length].decode()
    ), length


def parse_registration(data):
    header, header_length = parse_header(data)
    url_entry, url_entries_length = parse_url_entry(data[header_length:])

    result, length = _parse(data[header_length + url_entries_length:], 3)

    return header, url_entry, dict(
        service_type=result[0].decode(),
        scope_list=result[1].decode(),
        attr_list=result[2].decode()
    )


def parse_request(data):
    header, header_length = parse_header(data)
    result, length = _parse(data[header_length:], 5)
    return header, dict(
        service_type=result[1].decode(),
        scope_list=result[2].decode()
    )
