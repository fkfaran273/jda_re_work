import random, time
try:
    from getsleep import *
except ImportError:
    pass  # helpers (closestNumber/frange/formatting) are defined locally
from datetime import datetime

mobileInternetSpeed = {"Algeria": 5.96, "Argentina": 20.16, "Australia": 58.87, "Austria": 41.88, "Bahrain": 24.86,
                       "Bangladesh": 9.59, "Belgium": 50.07, "Bolivia": 17.91, "Brazil": 21.87, "Cambodia": 11.97,
                       "Cameroon": 13.11, "Canada": 65.9, "Chile": 19.34, "China": 28.89, "Colombia": 16.95,
                       "CostaRica": 19.35, "Croatia": 45.87, "CzechRepublic": 48.84, "Denmark": 50.59, "Egypt": 17.03,
                       "Finland": 42.16, "France": 45.17, "Germany": 31.93, "Ghana": 11.14, "Greece": 44.02,
                       "HongKong": 34.24, "Iceland": 0, "India": 10.31,"Indonesia": 10.51, "Iran": 29.82, "Ireland": 23.59,
                       "Israel": 23.63, "Italy": 32.2, "IvoryCoast": 21.84, "Japan": 31.39, "Jordan": 15.8,
                       "Kenya": 14.81, "Kuwait": 35.41, "Latvia": 30.59, "Lebanon": 39.82, "Luxembourg": 43.55,
                       "Malaysia": 20.49, "Mexico": 23.35, "Morocco": 23.79, "Myanmar": 23.11, "Netherlands": 60.6,
                       "NewZealand": 45.26, "Nigeria": 13.41, "Norway": 67.54, "Oman": 35.19, "Pakistan": 12.27,
                       "Peru": 23.98, "Philippines": 15.06, "Poland": 30.68, "Portugal": 33.78, "Qatar": 60.97,
                       "Romania": 35.94, "Russia": 19.54, "SaudiArabia": 33.02, "Senegal": 16.35, "Singapore": 53.69,
                       "Slovakia": 33.8, "Slovenia": 33.58, "SouthAfrica": 26.91, "SouthKorea": 54.89, "Spain": 34.66,
                       "SriLanka": 24.89, "Sweden": 49.79, "Switzerland": 51.93, "Taiwan": 43.12, "Tanzania": 10.34,
                       "Thailand": 19.08, "Tunisia": 22.45, "Turkey": 35.03, "Uganda": 10.17, "UK": 30.01,
                       "Ukraine": 18.15, "UnitedArabEmirates": 53.83, "USA": 34.55, "Vietnam": 22.45, "Yemen": 0}

wifiInternetSpeed = {"Algeria": 4.42, "Argentina": 25.25, "Australia": 35.11, "Austria": 37.2, "Bahrain": 42.12,
                     "Bangladesh": 19.77, "Belgium": 71.82, "Bolivia": 11.03, "Brazil": 32.62, "Cambodia": 16.07,
                     "Cameroon": 9.57, "Canada": 114.72, "Chile": 67.36, "China": 90.56, "Colombia": 17.87,
                     "CostaRica": 22.61, "Croatia": 31.5, "CzechRepublic": 47.94, "Denmark": 99.87, "Egypt": 6.94,
                     "Finland": 58.75, "France": 109.83, "Germany": 69.42, "Ghana": 20.95, "Greece": 22.99,
                     "HongKong": 168.69, "Iceland": 0, "India": 28.69, "Indonesia": 16.65, "Iran": 12.84, "Ireland": 60.34,
                     "Israel": 71.33, "Italy": 51.46, "IvoryCoast": 13.72, "Japan": 96.62, "Jordan": 33.56,
                     "Kenya": 16.12, "Kuwait": 24.32, "Latvia": 64.3, "Lebanon": 6.67, "Luxembourg": 107.6,
                     "Malaysia": 67.15, "Mexico": 27.64, "Morocco": 14.47, "Myanmar": 12.66, "Netherlands": 92.46,
                     "NewZealand": 87.92, "Nigeria": 11.15, "Norway": 105.9, "Oman": 19.96, "Pakistan": 8.47,
                     "Peru": 27.98, "Philippines": 19.51, "Poland": 68.83, "Portugal": 81.25, "Qatar": 64.53,
                     "Romania": 136.95, "Russia": 50.43, "SaudiArabia": 31.71, "Senegal": 15.33, "Singapore": 199.62,
                     "Slovakia": 57.01, "Slovenia": 56.21, "SouthAfrica": 19.47, "SouthKorea": 132.63, "Spain": 111.13,
                     "SriLanka": 22.63, "Sweden": 120.42, "Switzerland": 117.18, "Taiwan": 99.06, "Tanzania": 13.26,
                     "Thailand": 76.72, "Tunisia": 8.64, "Turkey": 21.27, "Uganda": 13.11, "UK": 58.84,
                     "Ukraine": 44.36, "UnitedArabEmirates": 58.63, "USA": 117.31, "Vietnam": 27.6, "Yemen": 2.96}

countryCodes = {"DZ": "Algeria", "AR": "Argentina", "AU": "Australia", "AT": "Austria", "BH": "Bahrain",
                "BD": "Bangladesh", "BE": "Belgium", "BO": "Bolivia", "BR": "Brazil", "KH": "Cambodia",
                "CM": "Cameroon", "CA": "Canada", "CL": "Chile", "CN": "China", "CO": "Colombia", "CR": "CostaRica",
                "HR": "Croatia", "CZ": "CzechRepublic", "DK": "Denmark", "EG": "Egypt", "FI": "Finland", "FR": "France",
                "DE": "Germany", "GH": "Ghana", "GR": "Greece", "HK": "HongKong", "IS": "Iceland", "IN": "India",
                "ID": "Indonesia", "IR": "Iran", "IE": "Ireland", "IL": "Israel", "IT": "Italy", "CI": "IvoryCoast",
                "JP": "Japan", "JO": "Jordan", "KE": "Kenya", "KW": "Kuwait", "LV": "Latvia", "LB": "Lebanon",
                "LU": "Luxembourg", "MO": "Macau", "MY": "Malaysia", "MX": "Mexico", "MA": "Morocco", "MM": "Myanmar",
                "NL": "Netherlands", "NZ": "NewZealand", "NG": "Nigeria", "NO": "Norway", "OM": "Oman",
                "PK": "Pakistan", "PE": "Peru", "PH": "Philippines", "PL": "Poland", "PT": "Portugal", "QA": "Qatar",
                "RO": "Romania", "RU": "Russia", "SA": "SaudiArabia", "SN": "Senegal", "SG": "Singapore",
                "SK": "Slovakia", "SI": "Slovenia", "ZA": "SouthAfrica", "KR": "SouthKorea", "ES": "Spain",
                "LK": "SriLanka", "SE": "Sweden", "CH": "Switzerland", "TW": "Taiwan", "TZ": "Tanzania",
                "TH": "Thailand", "TN": "Tunisia", "TR": "Turkey", "UG": "Uganda", "GB": "UK", "UA": "Ukraine",
                "AE": "UnitedArabEmirates", "US": "USA", "VN": "Vietnam", "YE": "Yemen"}



def main(app_data, device_data, app_size, os="android", min_sleep=0):
    times={}
    # Sleep for user to click on the install button............
    # if "click_time" in app_data.keys():
    #     if isinstance(app_data["click_time"], unicode):
    #         try:
    #             clickTime = app_data['click_time'].split('.')[0]
    #             app_data['click_time'] = time.mktime(datetime.strptime(clickTime, "%Y-%m-%dT%H:%M:%S").timetuple())
    #         except Exception as e:
    #             app_data["click_time"] = float(app_data["click_time"])
    #     elif isinstance(app_data["click_time"], str):
    #         try:
    #             clickTime = app_data['click_time'].split('.')[0]
    #             app_data['click_time'] = time.mktime(datetime.strptime(clickTime, "%Y-%m-%dT%H:%M:%S").timetuple())
    #         except Exception as e:
    #             app_data["click_time"] = float(app_data["click_time"])
            
    randomNumber = random.randint(1, 100)
    if randomNumber <= 70:
        clickSleep = random.randint(1, 3)
        if random.randint(1, 100) <= 20:
            clickSleep = random.uniform(5, 15)
    else:
        if app_size <= 100:
            randomNumber = random.randint(1, 100)
            if randomNumber <= 40:
                clickSleep = random.uniform(10, 60)
            elif randomNumber > 40 and randomNumber <= 70:
                clickSleep = random.uniform(60, 120)
            elif randomNumber > 70 and randomNumber <= 90:
                clickSleep = random.uniform(120, 300)
            else:
                clickSleep = random.uniform(300, 500)
        else:
            randomNumber = random.randint(1, 100)
            if randomNumber <= 40:
                clickSleep = random.uniform(30, 90)
            elif randomNumber > 40 and randomNumber <= 70:
                clickSleep = random.uniform(90, 180)
            elif randomNumber > 70 and randomNumber <= 90:
                clickSleep = random.uniform(180, 360)
            else:
                clickSleep = random.uniform(360, 720)

    # print(clickSleep)

    downloadSleep = downloadingApp(app_data, device_data, app_size)
    # print(downloadSleep)

    installSleep = installTime(app_data, device_data, app_size, os)
    # print(installSleep)

    sumSleep = clickSleep + downloadSleep + installSleep

    if min_sleep > 0 and sumSleep < min_sleep:
        extraSleep = min_sleep - sumSleep
        clickSleep += random.uniform(extraSleep, extraSleep + 3)

    if app_size<=100:
        if sumSleep > 600:
            extraSleep = sumSleep - 600
            extraSleep = random.uniform(extraSleep, extraSleep + random.randint(5, 20))
            if clickSleep > extraSleep:
                clickSleep -= extraSleep
            elif downloadSleep > extraSleep:
                downloadSleep -= extraSleep
            elif installSleep > extraSleep:
                installSleep -= extraSleep
            else:
                extraSleep = extraSleep / 2
                if clickSleep > extraSleep:
                    clickSleep -= extraSleep
                    if downloadSleep > extraSleep:
                        downloadSleep -= extraSleep
                elif downloadSleep > extraSleep:
                    downloadSleep -= extraSleep
                else:
                    installSleep -= extraSleep
    else:
        if sumSleep > 900:
            extraSleep = sumSleep - 900
            extraSleep = random.uniform(extraSleep, extraSleep + random.randint(5, 20))
            if clickSleep > extraSleep:
                clickSleep -= extraSleep
            elif downloadSleep > extraSleep:
                downloadSleep -= extraSleep
            elif installSleep > extraSleep:
                installSleep -= extraSleep
            else:
                extraSleep = extraSleep / 2
                if clickSleep > extraSleep:
                    clickSleep -= extraSleep
                    if downloadSleep > extraSleep:
                        downloadSleep -= extraSleep
                elif downloadSleep > extraSleep:
                    downloadSleep -= extraSleep
                else:
                    installSleep -= extraSleep

    sumSleep = clickSleep + downloadSleep + installSleep

    if "click_time" in app_data.keys():

        timeLapsedSinceClick= time.time()-app_data["click_time"]

        times['click_time'] = app_data["click_time"]
        times['download_begin_time'] = app_data["click_time"] + clickSleep
        times['download_end_time'] = app_data["click_time"] + clickSleep + downloadSleep
        times['install_complete_time'] = app_data["click_time"] + clickSleep + downloadSleep + installSleep

        if timeLapsedSinceClick < sumSleep:
            time.sleep(sumSleep - timeLapsedSinceClick)
    
    else:

        times['click_time'] = time.time()
        times['download_begin_time'] = time.time() + clickSleep

        times['download_end_time'] = time.time() + clickSleep + downloadSleep

        times['install_complete_time'] = time.time() + clickSleep + downloadSleep + installSleep

        print(sumSleep)
        # time.sleep(int(sumSleep))
        # return


    app_data["times"] = times

    return app_data["times"]

def downloadingApp(app_data, device_data, app_size):
    minSpeed = 0.5
    maxSpeed = 10
    downloadSleep = 0
    network = wifiInternetSpeed
    country = device_data["locale"]["country"]
    if country in countryCodes:
        country = countryCodes[country]
    
    if app_size>0:
        if app_size > 100:
            if random.randint(1, 100) <= 20:
                network = mobileInternetSpeed
        elif app_size > 50 and app_size <= 100:
            if random.randint(1, 100) <= 30:
                network = mobileInternetSpeed
        elif app_size > 20 and app_size <= 50:
            if random.randint(1, 100) <= 40:
                network = mobileInternetSpeed
        else:
            if random.randint(1, 100) <= 50:
                network = mobileInternetSpeed

        if country in network:
            if network[country] != 0:
                if random.randint(1, 100) <= 90:
                    minSpeed = round((network[country] / 3) / 8.0, 2)
                    maxSpeed = round((network[country] * 1.5) / 8.0, 2)
                else:
                    minSpeed = round((network[country] / 4) / 8.0, 2)
                    maxSpeed = round((network[country] * 1.5) / 8.0, 2)

        minDownloadSleep = app_size / maxSpeed
        maxDownloadSleep = app_size / minSpeed

        if maxDownloadSleep < 60.0:
            nearestNumber = closestNumber(minDownloadSleep, 10)
            sleepRange = list(frange(nearestNumber, maxDownloadSleep, jump=10))
            sleepRange.append(maxDownloadSleep)
            downloadSleep = formatting(len(sleepRange), minDownloadSleep, sleepRange)
            # print(downloadSleep)
            # print(sleepRange)

        else:
            nearestNumber = closestNumber(minDownloadSleep, 60)
            sleepRangeMinute = list(frange(nearestNumber, maxDownloadSleep, jump=60))
            sleepRangeMinute.append(maxDownloadSleep)
            # print(sleepRangeMinute)
            randomNumber = random.randint(1, 100)
            if len(sleepRangeMinute) == 1:
                nearestNumber = closestNumber(minDownloadSleep, 10)
                sleepRange = list(frange(nearestNumber, sleepRangeMinute[0], jump=10))
                sleepRange.append(sleepRangeMinute[0])
                downloadSleep = formatting(len(sleepRange), minDownloadSleep, sleepRange)
                
            elif len(sleepRangeMinute) == 2:
                if randomNumber <= 60:
                    nearestNumber = closestNumber(minDownloadSleep, 10)
                    sleepRange = list(frange(nearestNumber, sleepRangeMinute[0], jump=10))
                    sleepRange.append(sleepRangeMinute[0])
                    downloadSleep = formatting(len(sleepRange), minDownloadSleep, sleepRange)
                else:
                    sleepRange = list(frange(sleepRangeMinute[0] + 10, sleepRangeMinute[1], jump=10))
                    sleepRange.append(sleepRangeMinute[1])
                    downloadSleep = formatting(len(sleepRange), sleepRangeMinute[0], sleepRange)

            elif len(sleepRangeMinute) == 3:
                if randomNumber <= 50:
                    nearestNumber = closestNumber(minDownloadSleep, 10)
                    sleepRange = list(frange(nearestNumber, sleepRangeMinute[0], jump=10))
                    sleepRange.append(sleepRangeMinute[0])
                    downloadSleep = formatting(len(sleepRange), minDownloadSleep, sleepRange)
                elif randomNumber > 50 and randomNumber <= 80:
                    sleepRange = list(frange(sleepRangeMinute[0] + 10, sleepRangeMinute[1], jump=10))
                    sleepRange.append(sleepRangeMinute[1])
                    downloadSleep = formatting(len(sleepRange), sleepRangeMinute[0], sleepRange)
                else:
                    sleepRange = list(frange(sleepRangeMinute[1] + 10, sleepRangeMinute[2], jump=10))
                    sleepRange.append(sleepRangeMinute[2])
                    downloadSleep = formatting(len(sleepRange), sleepRangeMinute[1], sleepRange)

            else:
                if randomNumber <= 40:
                    nearestNumber = closestNumber(minDownloadSleep, 10)
                    sleepRange = list(frange(nearestNumber, sleepRangeMinute[0], jump=10))
                    sleepRange.append(sleepRangeMinute[0])
                    downloadSleep = formatting(len(sleepRange), minDownloadSleep, sleepRange)
                elif randomNumber > 40 and randomNumber <= 70:
                    sleepRange = list(frange(sleepRangeMinute[0] + 10, sleepRangeMinute[1], jump=10))
                    sleepRange.append(sleepRangeMinute[1])
                    downloadSleep = formatting(len(sleepRange), sleepRangeMinute[0], sleepRange)
                elif randomNumber > 70 and randomNumber <= 90:
                    sleepRange = list(frange(sleepRangeMinute[1] + 10, sleepRangeMinute[2], jump=10))
                    sleepRange.append(sleepRangeMinute[2])
                    downloadSleep = formatting(len(sleepRange), sleepRangeMinute[1], sleepRange)
                else:
                    sleepRange = list(
                        frange(sleepRangeMinute[2] + 10, sleepRangeMinute[len(sleepRangeMinute) - 1], jump=10))
                    sleepRange.append(sleepRangeMinute[len(sleepRangeMinute) - 1])
                    downloadSleep = formatting(len(sleepRange), sleepRangeMinute[2], sleepRange)

            # print(downloadSleep)
            # print(sleepRange)

    else:
        print("App Size is : ",app_size)

    # print(minDownloadSleep, maxDownloadSleep)
    return downloadSleep


def installTime(app_data, device_data, app_size, os):
    if os == "android":
        ram = 0
        os_version = device_data.get("os_version").split(".")
        if len(os_version) > 1:
            os_version1 = os_version[0] + "." + os_version[1]
        else:
            os_version1 = os_version[0] + ".0"
        os_version = float(os_version1)

        try:
            if type(device_data.get('ram')) is not str:
                if type(device_data.get("ram").get("shown")) is dict:
                    if device_data.get("ram").get("shown").get("shown") != "":
                        ramlower = device_data.get("ram").get("shown").get("shown").lower()
                        if "gb" in ramlower:
                            ram1 = ramlower
                            ram = ram1.strip('gb')
                            ram = int(ram) * 1024
                        else:
                            if device_data.get("ram").get("shown").get("shown") != "0":
                                ram = int(device_data.get("ram").get("shown").get("shown"))

                elif type(device_data.get("ram").get("shown")) is not dict:
                    if device_data.get("ram").get("shown") != "":
                        ramlower = device_data.get("ram").get("shown").lower()
                        if "gb" in ramlower:
                            ram1 = ramlower
                            ram = ram1.strip('gb')
                            ram = int(ram) * 1024
                        else:
                            if device_data.get("ram").get("shown") != "0":
                                ram = int(device_data.get("ram").get("shown"))
            else:
                if os_version < 6.0:
                    ram = random.choice([1024, 1024, 1024, 1024, 2048, 2048, 2048])
                if os_version >= 6.0:
                    ram = random.choice([1024, 1024, 2048, 2048, 2048, 3072, 3072, 3072, 4096, 4096])

        except Exception as e:
            if os_version < 6.0:
                ram = random.choice([1024, 1024, 1024, 1024, 2048, 2048, 2048])
            if os_version >= 6.0:
                ram = random.choice([1024, 1024, 2048, 2048, 2048, 3072, 3072, 3072, 4096, 4096])

        if ram == 0:
            if os_version < 6.0:
                ram = random.choice([1024, 1024, 1024, 1024, 1024, 2048, 2048])
            if os_version >= 6.0:
                ram = random.choice([1024, 1024, 2048, 2048, 2048, 2048, 2048, 3072, 3072, 4096])

        # print ram

        if ram <= 1024:
            if app_size <= 100.0:
                installsleep = app_size / (round(random.uniform(8.3, 9.5), 2) / 8)
            if app_size > 100.0 and app_size <= 250.0:
                installsleep = app_size / (round(random.uniform(13.5, 15.5), 2) / 8)
            if app_size > 250.0:
                installsleep = app_size / (round(random.uniform(25, 28), 2) / 8)

        if ram > 1024 and ram <= 2048:
            if app_size <= 100.0:
                installsleep = app_size / (round(random.uniform(10.5, 12.5), 2) / 8)
            if app_size > 100.0 and app_size <= 250.0:
                installsleep = app_size / (round(random.uniform(27, 30), 2) / 8)
            if app_size > 250.0:
                installsleep = app_size / (round(random.uniform(45, 55), 2) / 8)

        if ram > 2048 and ram <= 3072:
            if app_size <= 100.0:
                installsleep = app_size / (round(random.uniform(18, 23), 2) / 8)
            if app_size > 100.0 and app_size <= 250.0:
                installsleep = app_size / (round(random.uniform(45, 62), 2) / 8)
            if app_size > 250.0:
                installsleep = app_size / (round(random.uniform(70, 100), 2) / 8)

        if ram > 3072 and ram <= 4096:
            if app_size <= 100.0:
                installsleep = app_size / (round(random.uniform(29, 42), 2) / 8)
            if app_size > 100.0 and app_size <= 250.0:
                installsleep = app_size / (round(random.uniform(85, 110), 2) / 8)
            if app_size > 250.0:
                installsleep = app_size / (round(random.uniform(140, 200), 2) / 8)

        if ram > 4096:
            if app_size <= 100.0:
                installsleep = app_size / (round(random.uniform(50, 80), 2) / 8)
            if app_size > 100.0 and app_size <= 250.0:
                installsleep = app_size / (round(random.uniform(150, 200), 2) / 8)
            if app_size > 250.0:
                installsleep = app_size / (round(random.uniform(280, 400), 2) / 8)

    else:
        if app_size <= 100.0:
            installsleep = app_size / (round(random.uniform(50, 80), 2) / 8)
        if app_size > 100.0 and app_size <= 250.0:
            installsleep = app_size / (round(random.uniform(150, 200), 2) / 8)
        if app_size > 250.0:
            installsleep = app_size / (round(random.uniform(280, 400), 2) / 8)

    # print(installsleep)
    return installsleep


def formatting(lengthSleepRange, minDownloadSleep, sleepRange):
    randomNumber = random.randint(1, 100)
    if lengthSleepRange == 1:
        downloadSleep = random.uniform(minDownloadSleep, sleepRange[0])
    elif lengthSleepRange == 2:
        if randomNumber <= 60:
            downloadSleep = random.uniform(minDownloadSleep, sleepRange[0])
        else:
            downloadSleep = random.uniform(sleepRange[0], sleepRange[1])
    elif lengthSleepRange == 3:
        if randomNumber <= 50:
            downloadSleep = random.uniform(minDownloadSleep, sleepRange[0])
        elif randomNumber > 50 and randomNumber <= 80:
            downloadSleep = random.uniform(sleepRange[0], sleepRange[1])
        else:
            downloadSleep = random.uniform(sleepRange[1], sleepRange[2])
    else:
        if randomNumber <= 40:
            downloadSleep = random.uniform(minDownloadSleep, sleepRange[0])
        elif randomNumber > 40 and randomNumber <= 70:
            downloadSleep = random.uniform(sleepRange[0], sleepRange[1])
        elif randomNumber > 70 and randomNumber <= 90:
            downloadSleep = random.uniform(sleepRange[1], sleepRange[2])
        else:
            downloadSleep = random.uniform(sleepRange[2], sleepRange[lengthSleepRange - 1])

    return downloadSleep


def closestNumber(n, m):
    # Find the quotient
    q = int(n / m)

    # 1st possible closest number
    n1 = m * q

    # 2nd possible closest number
    if ((n * m) > 0):
        n2 = (m * (q + 1))
    else:
        n2 = (m * (q - 1))

    # n2 is the required closest number
    return n2


def frange(x, y, jump):
    while x < y:
        yield x
        x += jump


# if __name__ == '__main__':
#     # for i in range(1000):
#     generateTime(app_data, device_data, app_size=150)
