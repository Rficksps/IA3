from flask import Flask, render_template
import requests
import datetime

app = Flask(__name__)

# Replace 'your_client_id' and 'your_access_token' with your actual IGDB credentials
CLIENT_ID = 'pv15nlewbuw35bxzu7m3b14bbge8pl'
ACCESS_TOKEN = ('t7kx1w6sqe0ynn4bqkcrmbqhpfs49i')
HEADERS = {
    'Client-ID': CLIENT_ID,
    'Authorization': f'Bearer {ACCESS_TOKEN}'
}

def get_recent_games():
    now = datetime.datetime.now()
    thirty_days_ago = now - datetime.timedelta(days=30)
    timestamp_now = int(now.timestamp())
    timestamp_thirty_days_ago = int(thirty_days_ago.timestamp())

    url = 'https://api.igdb.com/v4/games'
    query = f'''
        fields name, first_release_date, cover.url;
        where first_release_date >= {timestamp_thirty_days_ago} & first_release_date <= {timestamp_now};
        sort first_release_date desc;
        limit 50;
    '''

    response = requests.post(url, headers=HEADERS, data=query)
    if response.status_code == 200:
        games = response.json()
        print(f"Number of games retrieved: {len(games)}")  # Debugging line
        return games
    else:
        print(f"Error fetching games: {response.status_code}, {response.text}")  # Debugging line
        return []

@app.template_filter('datetimeformat')
def datetimeformat(value):
    return datetime.datetime.fromtimestamp(value).strftime('%Y-%m-%d')

@app.route('/')
def index():
    games = get_recent_games()
    return render_template('index.html', games=games)

if __name__ == '__main__':
    app.run(debug=True)
