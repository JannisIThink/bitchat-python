


def getGeoPosition() -> str|None:
	#return None if no GPS module is avaliable.
	return "DummyGeoPosition"




if __name__ == "__main__":
	print(getGeoPosition())