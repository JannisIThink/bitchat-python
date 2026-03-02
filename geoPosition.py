
import serial
import pynmea2

class GPSModule:
	def __init__(self):
		self.ser = serial.Serial(port="/dev/ttyACM0",baudrate=9600,timeout=1)

	def tryGetPosition(self):
		for _ in range(30):
			line = self.ser.readline().decode("ascii",errors="replace").strip()
			if not line:
				continue
			else:
				res = self.parse_gga(line)
				print(res)


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
        "num_sats": msg.num_sats,
        "hdop": msg.horizontal_dil,
    	}



def getGeoPosition(self) -> str|None:
	#return None if no GPS module is avaliable.
	return "DummyGeoPosition"




if __name__ == "__main__":
	print(getGeoPosition())