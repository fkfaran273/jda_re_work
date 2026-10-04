import random


def getnetworktype(app_size, day, os_type):
    network_type = calculate_network_type(app_size, day)

    if os_type == "ios":
        network_type = ios_network_type(network_type)

    return network_type


def calculate_network_type(app_size, day):
    if day == "install" or day == "Install":
        if app_size:
            if app_size >= 0 and app_size < 50:
                return generate_values(60)
            elif app_size >= 50 and app_size < 200:
                return generate_values(30)
            elif app_size >= 200 and app_size < 1024:
                return generate_values(10)
            else:
                return generate_values(5)
    else:
        return generate_values(60)


def ios_network_type(network_type):
    if network_type == "WIFI":
        return True
    else:
        return False


def generate_values(per):
    if random.randint(1, 100) <= per:
        return "MOBILE"
    else:
        return "WIFI"