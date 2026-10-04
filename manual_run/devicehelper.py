class UserAgent(object):

    @staticmethod
    def dalvik_agent(device_data):
        return 'Dalvik/{0} (Linux; U; Android {1}; {2} Build/{3})'.format(
            "2.1.0" if int(device_data.get("sdk")) >= 19 else "1.6.0",
            device_data.get('os_version'), device_data.get('model'), device_data.get('build')
        )

    @staticmethod
    def darwin_agent(app_name, app_version_code, device_data):
        cfnetwork = str(device_data.get('cfnetwork')).split("_")
        return "{0}/{1} CFNetwork/{2} Darwin/{3}".format(
            app_name, app_version_code, cfnetwork[0],
            cfnetwork[1] if len(cfnetwork) > 1 else ""
        )
