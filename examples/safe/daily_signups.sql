-- signups per day, last 30 days
SELECT date_trunc('day', created_at) AS day,
       count(*) AS signups
FROM users
WHERE created_at >= current_date - interval '30 days'
GROUP BY 1
ORDER BY 1;
