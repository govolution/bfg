int dummyCompute(long long iterations, int seed) {
	int result = seed;
	long long i = 0;
	while(i < iterations) {
		result++;
		result = result * seed;
		result = result * result;
		result = result + (2 * seed) + 3;		
		i++;
	}
}