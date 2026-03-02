
import serial
import pynmea2

class GPSModule:
	def __init__(self):
		self.works = True
		try:
			self.ser = serial.Serial(port="/dev/ttyACM0",baudrate=9600,timeout=1)
		except Exception:
			self.ser = None
			self.works = False

	def tryGetPosition(self) -> str|None:
		""" Versucht die aktuelle Position zu bestimmen und returnt None, wenn keien Position ermittelt werden konnte."""
		if not self.works:
			return None
		for _ in range(30):
			line = self.ser.readline().decode("ascii",errors="replace").strip()
			if not line:
				continue
			else:
				res = self.parse_gga(line)
				if res and (res["latitude"] != 0.0) and (res["longitude"] != 0.0) and (res["gps_qual"] != 0) and (res["num_sats"] >= 4):
					return f"{res['latitude']};{res["longitude"]};{res["gps_qual"]};{res['num_sats']};{res["hdop"]}"
		return None


	def parse_gga(self, sentence: str) -> dict | None:
		"""
		Parst ausschließlich GGA-Sätze und extrahiert alle Parameter.
		"""
		try:
			msg = pynmea2.parse(sentence)
		except pynmea2.ParseError:
			return None

		if msg.sentence_type != "GGA":
			return None

		return {
        "timestamp": msg.timestamp,
        "latitude": msg.latitude,
        "longitude": msg.longitude,
        "altitude": msg.altitude,
        "gps_qual": msg.gps_qual,
        "num_sats": int(msg.num_sats),
        "hdop": float(msg.horizontal_dil),
    	}

	def getGeoPosition(self) -> str|None:
		return self.tryGetPosition()




if __name__ == "__main__":
	print(GPSModule().getGeoPosition())