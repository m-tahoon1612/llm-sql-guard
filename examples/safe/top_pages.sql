WITH recent AS (
    SELECT page_path, user_id
    FROM pageviews
    WHERE event_date = '2026-10-01'
)
SELECT page_path, count(DISTINCT user_id) AS users
FROM recent
GROUP BY page_path
ORDER BY users DESC
LIMIT 20
