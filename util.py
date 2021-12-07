import scapy


def compare_layers(layer1, layer2):
    """Compare the fields of two scapy layers/headers of the same type.

    Differences are returned as tuples of field name, value in `layer1` and value in `layer2`.
    Packet fields and PacketListFields are compared recursively.
    """
    for desc in layer1.fields_desc:
        a = getattr(layer1, desc.name)
        b = getattr(layer2, desc.name)
        if issubclass(type(a), scapy.packet.Packet):
            yield from compare_layers(a, b)
        elif isinstance(desc, scapy.fields.PacketListField):
            for i, (sublayer1, sublayer2) in enumerate(zip(a, b)):
                for diff in compare_layers(sublayer1, sublayer2):
                    yield ("{}[{}]/{}".format(desc.name, i, diff[0]), diff[1], diff[2])
        else:
            if a != b:
                yield (desc.name, a, b)
