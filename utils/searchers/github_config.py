from scipy.stats import norm

mus = [300, 30, 0]  # average
sigmas = [500, 25, 800]  # standard deviation
max_confs = [0.8, 0.6, 0.7] # max confidence
conf_score_weights = [0.6, 0.3, 0.1]
base_line = 0.75
times_0 = max_confs[0] / norm.pdf(mus[0], loc=mus[0], scale=sigmas[0]) # scaling times
times_1 = max_confs[1] / norm.pdf(mus[1], loc=mus[1], scale=sigmas[1])
times_2 = (1 - base_line) / norm.pdf(mus[2], loc=mus[2], scale=sigmas[2])
threshold = 0.45 # judgement threshold
total_stars_count = 0 # init
total_forks_count = 0 # init
base_limit = 30
trend_weights = [1, 1]
alpha = 1.2
size_limits = [10, 200, 1000]
file_num_limits = 10
per_page = 10
count_each_keyword = 10
remove_wieghts = [0.8, 0.2]